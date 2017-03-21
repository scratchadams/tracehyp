

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

//to allow root to use icmp run:
//sysctl -w net.ipv4.ping_group_range="0 0"

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

void trace(struct in_addr *dst, int send_cnt) {
    struct icmphdr icmp_hdr;
    struct sockaddr_in addr;
    int sequence = 0;
    unsigned char data[2048]; // Packet data

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int ch;
    int count = 0;
    struct timeval timeout = {5, 0};
    fd_set read_set;
    socklen_t slen;
    struct icmphdr rcv_hdr;

    int on = 1;
    int ttl = 1;
    int hops = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    /*if((setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
        perror("setsockopt");
    }

    setsockopt(sock, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));
    //setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    */
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if(sock < 0) {
        perror("socket");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = *dst;
    addr.sin_port = 0;

    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.checksum = 0;
    icmp_hdr.un.echo.id = 1189;

    for (;;) {
        usleep(120000);

        //sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if((setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
            perror("setsockopt");
            break;
        }
        setsockopt(sock, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));
        //setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        struct sockaddr_in address;
        char ip4[INET_ADDRSTRLEN];
        char ip_compare[INET_ADDRSTRLEN];

        memcpy(data, &icmp_hdr, sizeof(icmp_hdr));
        memcpy(data + sizeof(icmp_hdr), "hello", 5); //icmp payload

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
        FD_SET(sock, &read_set);

        //wait for a timeout
        if((ch = select(sock+1, &read_set, NULL, NULL, &timeout)) == 0)
        {
            printf("Timeout\n");
            break;

        } else if (ch < 0) {
            perror("select");
            break;

        }

        // we want dat sender address
        slen = INET_ADDRSTRLEN;
        if((ch = recvfrom(sock, data, sizeof(data), 0,
                        (struct sockaddr*)&address, &slen)) <= 0)
        {
            //perror("recverror");
            continue;

        } else if (ch < sizeof(rcv_hdr)) {
            printf("Error, got short ICMP packet, %d bytes\n", ch);
            break;

        }

        inet_ntop(AF_INET, &(address.sin_addr),ip4, INET_ADDRSTRLEN);
        printf("Address: %s Hops: %d\n", ip4, hops);

        inet_ntop(AF_INET, &(addr.sin_addr), ip_compare, INET_ADDRSTRLEN);
        if(strcmp(ip4,ip_compare) == 0)
            break;

        //close(sock);
        ttl++;
        hops++;
        continue;

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
    struct hostent *host = gethostbyname(argv[1]);
    struct in_addr **addr_list;
    char *con_addr;

    addr_list = (struct in_addr **)host->h_addr_list;

    for(i = 0; addr_list[i] !=NULL; i++) {
        con_addr = inet_ntoa(*addr_list[i]);
        printf("%s \n", con_addr);
    }

    dst = (struct in_addr *)addr_list[0];
    trace(dst, 5);
    return 0;
}
