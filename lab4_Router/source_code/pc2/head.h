#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define DEVICE_FILE "./config/device.file"
#define IP_FILE "./config/ip.file"
#define DEFAULT_GATEWAY_FILE "./config/gateway.file"
#define ARP_FILE "./config/arp_table.file"


#define MAX_DEVICE 10
#define MAX_ARP_SIZE 10

struct device_item {
    char interface[14];
    char mac[6];
} device[MAX_DEVICE];
int n_dev;

struct ip_item {
	char interface[14];
	char ip[4];
} ip_table[MAX_DEVICE];
int n_ip;

struct arp_table_item {
    char ip[4];
    char mac[6];
} arp_table[MAX_ARP_SIZE];
int n_arp;

char gateway[4];

int index_ip, index_arp, index_interface;

FILE *fp;

char recv_buf[128];
char send_buf[128];
char send_arp_buf[42];
char recv_arp_buf[42];
char send_icmp_buf[98];
char recv_icmp_buf[98];
int n_send;

char tmp_mac_addr[18], tmp_ip_addr[14];

int sock_raw_fd, i;

struct sockaddr_ll saddr_11;
struct sockaddr_in src_addr;    
struct ifreq ifr;

void init_file();

uint8_t MyStoi(char *p, int n, int base);
int IPtoi(char *ip_addr);
void StoMac(char *src, char *dst);
void StoIP(char *src, char *dst);


int ARP_index(char *);
int IP_index(char *);
int MAC_index(char *);
int Interface_index_of_MAC(char *);

uint16_t check_sum(uint16_t *buf, int len);

void recv_packet();

void err_exit(const char *err_msg);

void Get_ARP_Index(char *);

