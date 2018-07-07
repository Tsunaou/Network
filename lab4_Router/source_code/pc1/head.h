#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
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
#define MAX_ROUTE_INFO 10

/* 以太网帧首部长度 */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* 整个arp结构长度 */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* 以太网 + 整个arp结构长度 */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
/* IP地址长度 */
#define IP_ADDR_LEN 4
/* 广播地址 */
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define MAX_NO_OF_PACKETS       12        //最大发包数目
#define MAX_SIZE_OF_PACKERTS    128        //一次ping操作最多发送的数据包
#define ICMP_HDR_LEN sizeof(struct icmphdr)



typedef struct Packets_Status
{
    struct timeval begin_time;  //发送包时间
    struct timeval end_time;    //接收包时间
    bool flag;                  //是否到达标志
    int seq;                    //序列号
}Packets_Status;

Packets_Status Packets[MAX_SIZE_OF_PACKERTS];
int n_Send;     //发送的包数量
int n_Recv;     //接收的包数量

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

struct route_item {
    char destination[16];
    char gateway[16];
    char netmask[16];
    char interface[16];
} route_info[MAX_ROUTE_INFO]; 
int n_route;

uint16_t my_pid;

int index_ip, index_arp;

FILE *fp;

char send_icmp_buf[98];
char recv_icmp_buf[98];
//int n_send;

char tmp_mac_addr[18], tmp_ip_addr[14];
int sock_raw_fd, ret_len, i;

struct sockaddr_ll saddr_11;
struct ifreq ifr;


void init_file();

uint8_t MyStoi(char *p, int n, int base);
void StoMac(char *src, char *dst);
void StoIP(char *src, char *dst);


uint16_t check_sum(uint16_t *buf, int len);

void send_icmp(char* src_mac, char *dst_mac, char* src_ip, char* dst_ip);	//发送ICMP包
double Cal_Time_Costs(struct timeval begin, struct timeval end);	//计算送begin到end历时多久

void err_exit(const char *err_msg);


