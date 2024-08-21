#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

// 특정 IP의 MAC 주소를 ARP 요청으로 가져오는 함수
void get_mac_from_ip(char *iface, char *ip, unsigned char *mac) {
    int sock;
    struct sockaddr_in target;
    struct arpreq req;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    target.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &target.sin_addr);

    memset(&req, 0, sizeof(req));
    memcpy(&req.arp_pa, &target, sizeof(target));
    strcpy(req.arp_dev, iface);

    if (ioctl(sock, SIOCGARP, &req) == -1) {
        perror("ioctl");
        close(sock);
        exit(1);
    }

    memcpy(mac, req.arp_ha.sa_data, 6);
    close(sock);
}

int main(int argc, char *argv[]) {
    char iface[] = "wlan0"; // 사용할 네트워크 인터페이스 (wlan0)
    unsigned char target_mac[6];

    if (argc != 2) {
        printf("Usage: %s <target IP>\n", argv[0]);
        return 1;
    }

    // 타겟 IP의 MAC 주소 가져오기
    get_mac_from_ip(iface, argv[1], target_mac);
    printf("Target IP (%s) MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           argv[1], target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

    return 0;
}

