#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <pthread.h>
#include <ncurses.h>

#define ARRSIZE 100

//to allow root to use icmp run:
//sysctl -w net.ipv4.ping_group_range="0 0"

WINDOW *create_newwin(int height, int width, int starty, int startx);
void destroy_win(WINDOW *local_win);

typedef struct {
    char ip_address[INET_ADDRSTRLEN];
    int ttl;
} ip_struct;

WINDOW *create_newwin(int height, int width, int starty, int startx) {
    WINDOW *local_win;

    local_win = newwin(height, width, starty, startx);
    box(local_win, 0, 0);

    wrefresh(local_win);
    return local_win;
}

void destroy_win(WINDOW *local_win) {
    wborder(local_win, ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ');
    wrefresh(local_win);
    delwin(local_win);
}

static WINDOW *trace_win;

void *probe_thread(void *ip_info) {
    ip_struct address_info = *((ip_struct*)(ip_info));
    //address_info = malloc(sizeof(address_info));
    
    //printf("made it further\n");
    if((strlen(address_info.ip_address)) > 3)
        wprintw(stdscr, "here - %s\n", address_info.ip_address);
	    refresh();
        probe_hop(address_info.ip_address, address_info.ttl);
}
    
//This function will probe the individual hop and return the number of 
//milliseconds it takes in order to receive the response from the hop
int probe_hop(char ip_address[INET_ADDRSTRLEN], int ttl) {
    struct hostent *host = gethostbyname(ip_address);
    struct in_addr **addr_list;
    struct in_addr *dst;

    addr_list = (struct in_addr **)host->h_addr_list;

    dst = (struct in_addr *)addr_list[0];
    trace_hop(dst, 5, ttl);
    //printf("probing: %s with TTL: %d\n", ip_address, ttl);
    return 0;
}

//This function will handle the creation of new threads in order to gather
//information from each individual hop, as well as the
int handle_hops(char *ip_add, int hopcount) {
    pthread_t threads[ARRSIZE];
    int i, rc;
    ip_struct *addr_info;
    addr_info = malloc(sizeof(addr_info));
    int hop = 1;

    char *str = "8.8.8.8";

    initscr();
    //trace_win = create_newwin(100, 150, 0, 0);
    //struct hostent *host = gethostbyname(ip_list[0]);

    for(i = 0;i < hopcount; i++ ) {
        //printf("list - %s - size - %d\n", ip_list[i], strlen(ip_list[i]));
        
        //if (strlen(ip_list[i]) == 0)
        //    continue;

	    //addr_info->ip_address = ip_list[i];
        strncpy(addr_info->ip_address, ip_add, strlen(ip_add));
        addr_info->ip_address[strlen(ip_add)] = '\0';
        addr_info->ttl = hop;
        hop++;
	
        //printf("made it\n");
	    rc = pthread_create(&threads[i], NULL, probe_thread, addr_info);
	    pthread_join(threads[i], NULL);
        //int test = probe_hop("8.8.8.8", hop);
	    
    }
    getch();
    //destroy_win(trace_win);
    endwin();
    //free(addr_info);

    return 0;
}

//This function calculates the ICMP checksum, based off of the ICMP header and it's data
//the len value should be set to sizeof(icmp_header) + (length of ICMP data) to account for
//both the header and it's contained data.
//The checksum formula is noted in RFC792 as:
//The checksum is the 16-bit ones's complement of the one's
//complement sum of the ICMP message starting with the ICMP Type.
//For computing the checksum , the checksum field should be zero, then replaced with checksum before sending.
uint16_t chk_sum(void *buffer, int len) {
    unsigned short *buf = buffer;
    unsigned int sum = 0;
    unsigned short result;

    for(sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if(len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    result = ~sum;
    return result;
}

int starr_print(char *newarray[], char strarray[ARRSIZE][INET_ADDRSTRLEN], int arrsize) {
    int i;
    int a = 0;

    for(i = 0;i < arrsize; i++) {
	if(strlen(strarray[i]) > 5) {
	    printf("%s added\n", strarray[i]);
	    newarray[a] = strarray[i];
	    a++;
	} else {
	    printf("%s not added at %u length\n", strarray[i], (unsigned)strlen(strarray[i]));
	}
        //printf("Address %d: %s size: %u\n", i, strarray[i], (unsigned)strlen(strarray[i]));
    }
    
    return 0;
}

//This function does all the heavy lifting
//It takes the argument dst which is a structure containing the
//destination information, and performs a traceroute against it.
void init_trace(struct in_addr *dst, int send_cnt) {
    //define structures for header and address information
    struct icmphdr icmp_hdr;
    struct sockaddr_in addr;
    struct icmphdr rcv_hdr;
    //struct in_addr holdaddr;

    //define structures for timeout information
    struct timeval timeout = {5, 0};
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    //various variables
    unsigned char data[2048]; // Packet data
    char oldip[INET_ADDRSTRLEN]; //hold the value of previous IP address
    char iparray[ARRSIZE][INET_ADDRSTRLEN];
    char *new_iparray[ARRSIZE];

    int ch;
    int count = 0;
    int on = 1;
    int ttl = 1;
    int hops = 1;
    int sequence = 0;

    fd_set read_set;
    socklen_t slen;
       
    //Open a raw socket with the ICMP protocol and make sure it opens properly
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock < 0) {
        perror("socket");
        return;
    }

    //Make this socket reusable
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    //Prepare address structure and fill it with the proper address and port information
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = *dst;
    addr.sin_port = 0;

    //Prepare header structure with ICMP_ECHO as the type for an icmp echo request
    //set the checksum to 0 which will be calculated later.
    //set any arbitrary ID
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.checksum = 0;
    icmp_hdr.un.echo.id = 1189;

    char ip_compare[INET_ADDRSTRLEN];

    for (;;) {
        //printf("Start loop\n");
        //usleep(120000);

        //sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        //This option sets the TTL value on the packet
        //This is very important for traceroute, as it uses incrementing TTL values
        //in order to determine how many hops away the destination is (as well as every machine in between)
        if((setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
            perror("setsockopt");
            break;
        }

        //This option sets the socket to receive errors.
        //This is important, because the host needs to receive a TTL exceeded message
        //from each host it hits on its way to the destination.
        //By receiving these messages, we are able to determine all of the hosts
        //between us and the destination as well as how many hops away each of these hosts are
        if((setsockopt(sock, IPPROTO_IP, IP_RECVERR, &on, sizeof(on))) < 0) {
            perror("setsockopt");
            break;
        }
        if((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0) {
            perror("setsockopt");
            break;
        }

        //Ip address structure and variables
        struct sockaddr_in address;
        char ip4[INET_ADDRSTRLEN];
        //char ip_compare[INET_ADDRSTRLEN];

        //copy the ICMP header information into data char array
        //then copy the "hello" data into the data char array in the position following the header
        memcpy(data, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(data + sizeof(icmp_hdr), "hello", 5); //icmp payload

        int i;
        icmp_hdr.checksum = 0; // Reset checksum for each packet

        //Generate ICMP checksum then replace the old ICMP header info in data array using memcpy
        icmp_hdr.checksum = chk_sum(data, sizeof(icmp_hdr)+5);
        memcpy(data, &icmp_hdr, sizeof(icmp_hdr));

        //Attempt to send ICMP echo request
        if((ch = sendto(sock, data, sizeof(icmp_hdr) + 5,
                0, (struct sockaddr*)&addr, sizeof(addr))) <= 0)
        {
            perror("sendto");
            break;
        }

        //Create a set that holds the socket information
        memset(&read_set, 0, sizeof(read_set));
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);

        //Using select, find out when socket is available to recv
        //This timesout after 5 seconds
        ch = select(sock+1, &read_set, NULL, NULL, &timeout);
        //printf("select returns: %d\n", ch);

        if(ch == 0)
        {
            printf("Timeout\n");
            break;

        } else if (ch < 0) {
            perror("select");
            break;

         } else {

            // Receive packet on the socket and gather the address information from the sender
            slen = INET_ADDRSTRLEN;
            if((ch = recvfrom(sock, data, sizeof(data), 0,
                           (struct sockaddr*)&address, &slen)) <= 0)
            {
                if(count > 5) {
		            strncpy(oldip, ip4, sizeof(oldip));
		            //strncpy(iparray[hops], ip4, sizeof(iparray[hops]));
                    count = 0;
                    ttl++;
                    hops++;
                    continue;
                }

                //printf("recv from return: %d\n", ch);
                count++;
                continue;

            } else if (ch < sizeof(rcv_hdr)) {
                printf("Error, got short ICMP packet, %d bytes\n", ch);
                break;

            }
            count = 0;

            struct hostent *he;
	        
            //Convert the sender address information to a readable format then print
            inet_ntop(AF_INET, &(address.sin_addr),ip4, INET_ADDRSTRLEN);
            he = gethostbyaddr(&(address.sin_addr), sizeof(address.sin_addr), AF_INET);
	    
	    if(strncmp(oldip, ip4, sizeof(oldip)) == 0) {
		    //printf("new ip: %s\n", ip4);
		    //printf("old ip: %s hops: %d\n", oldip, hops);
		    continue;
	    }
	    if(he != NULL)
		    printf("Host: %s Address: %s Hops: %d\n", he->h_name, ip4, hops);
	    else
		    printf("Address: %s Hops: %d\n", ip4, hops);

            //Convert and compare the address of the destination with the address of the sender
            //if the sender == the destination than the process ends and the socket is closed.
            inet_ntop(AF_INET, &(addr.sin_addr), ip_compare, INET_ADDRSTRLEN);
            if(strcmp(ip4,ip_compare) == 0) {
		        strncpy(iparray[hops], ip4, sizeof(iparray[hops]));
                break;
            }

            //increment the TTL along with number of hops
            //(this represents the same thing, but was getting weird results when printing ttl)
            strncpy(oldip, ip4, sizeof(oldip));
	        strncpy(iparray[hops], ip4, sizeof(iparray[hops]));
	        
            ttl++;
            hops++;
            continue;
        }
    }
    //starr_print(new_iparray, iparray, hops);
    close(sock);
    handle_hops(ip_compare, hops);
    //close(sock);
}

void trace_hop(struct in_addr *dst, int send_cnt, int hopnum) {
	struct icmphdr icmp_hdr;
	struct sockaddr_in addr;
	struct icmphdr rcv_hdr;

	struct timeval timeout = {5, 0};
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	unsigned char data[2048];
	char iparray[ARRSIZE][INET_ADDRSTRLEN];

	int ch;
	int count, sequence = 0;
	int on, hops = 1;
    int ttl = hopnum;
    int y, x;

	fd_set read_set;
	socklen_t slen;

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		perror("socket");
		return;
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = *dst;
	addr.sin_port = 0;

	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	icmp_hdr.type = ICMP_ECHO;
	icmp_hdr.checksum = 0;
	icmp_hdr.un.echo.id = 1191; //make this random

	char ip_compare[INET_ADDRSTRLEN];
    
    for (;;) {

        if((setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
		    perror("setsockopt");
		    break;
	    }

	    if((setsockopt(sock, IPPROTO_IP, IP_RECVERR, &on, sizeof(on))) < 0) {
		    perror("setsockopt");
		    break;
	    }
	    if((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))) < 0 ) {
		    perror("setsockopt");
		    break;
	    }

	    struct sockaddr_in address;
	    char ip4[INET_ADDRSTRLEN];
	    //char ip_compare[INET_ADDRSTRLEN];

	    memcpy(data, &icmp_hdr, sizeof(icmp_hdr));
	    memcpy(data + sizeof(icmp_hdr), "hello", 5);

	    int i;
	    icmp_hdr.checksum = 0;

	    icmp_hdr.checksum = chk_sum(data, sizeof(icmp_hdr)+5);
	    memcpy(data, &icmp_hdr, sizeof(icmp_hdr));

        if((ch = sendto(sock, data, sizeof(icmp_hdr) + 5,
                0, (struct sockaddr*)&addr, sizeof(addr))) <= 0)
        {
            perror("sendto");
            break;
        }

        memset(&read_set, 0, sizeof(read_set));
        FD_ZERO(&read_set);
        FD_SET(sock, &read_set);

        ch = select(sock+1, &read_set, NULL, NULL, &timeout);

        if(ch == 0) {
            getyx(stdscr, y, x);
            wprintw(stdscr, "y: %d and x: %d\n", y, x);
            wprintw(stdscr, "timeout\n");
            refresh();
            break;

        } else if (ch < 0) {
            perror("select");
            break;

        } else {
            
            slen = INET_ADDRSTRLEN;
            if((ch = recvfrom(sock, data, sizeof(data), 0,
                            (struct sockaddr*)&address, &slen)) <= 0)
            {
                if(count > 5) {
                    printf("Nothing\n");
                    break;
                }
                count++;
                continue;
            } else if (ch < sizeof(rcv_hdr)) {
                printf("Error, got short ICMP packet, %d bytes\n", ch);
                break;
            }
            count = 0;

            struct hostent *he;

            inet_ntop(AF_INET, &(address.sin_addr), ip4, INET_ADDRSTRLEN);
            he = gethostbyaddr(&(address.sin_addr), sizeof(address.sin_addr), AF_INET);

            if(he != NULL) {
                getyx(stdscr, y, x);
                wprintw(stdscr, "y: %d and x: %d\n", y, x);
                wprintw(stdscr, "Host: %s Address: %s Hops: %d\n", he->h_name, ip4, hopnum);
                refresh();
                break;
            } else {
                getyx(stdscr, y, x);
                wprintw(stdscr, "y: %d and x: %d\n", y, x);
                wprintw(stdscr, "Address: %s Hops: %d\n", ip4, hopnum);
                refresh();
                break;
            }

        }
    }
    close(sock);
}
int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("usage: %s destination_ip\n", argv[0]);
        return 1;
    }

    int i;
    struct in_addr *dst;
    struct hostent *host = gethostbyname(argv[1]); //Grab ip from argument (can be domain or IP)
    struct in_addr **addr_list;
    char *con_addr;

    addr_list = (struct in_addr **)host->h_addr_list;

    //Find IP addresses associated with Host and print them out
    for(i = 0; addr_list[i] !=NULL; i++) {
        con_addr = inet_ntoa(*addr_list[i]);
        printf("%s \n", con_addr);
    }

    //Set destination to first ip in address list
    dst = (struct in_addr *)addr_list[0];

    //Begin the trace!
    init_trace(dst, 5);
    //trace_hop(dst, 5, 3);
    //probe_hop(argv[1], 3);
    return 0;
}


