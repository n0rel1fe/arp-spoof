#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>

int main() {
    struct ifaddrs *ifaddr, *ifa;
    char ip[INET_ADDRSTRLEN] = {0};  // IP 주소를 저장할 변수
    unsigned char mac[6] = {0};      // MAC 주소를 저장할 배열
    int found = 0;

    // 네트워크 인터페이스 목록을 가져옴
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // 네트워크 인터페이스 목록 순회
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // 인터페이스 이름이 "wlan"으로 시작하는지 확인
        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            // AF_INET을 지원하는 인터페이스에서 IP 주소 가져오기
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
                found = 1;

                // 소켓을 사용하여 MAC 주소 가져오기
                int sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sock == -1) {
                    perror("socket");
                    exit(EXIT_FAILURE);
                }

                struct ifreq ifr;
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
                ifr.ifr_name[IFNAMSIZ-1] = '\0';

                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                } else {
                    perror("ioctl");
                }

                close(sock);
                break; // 첫 번째 wlan 인터페이스를 찾으면 종료
            }
        }
    }

    // 메모리 해제
    freeifaddrs(ifaddr);

    // 결과 출력
    if (found) {
        printf("Interface: wlan\n");
        printf("IP Address: %s\n", ip);
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        printf("No wlan interface found.\n");
    }

    return 0;
}

