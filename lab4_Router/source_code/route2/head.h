#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

//文件路径
#define DEVICE_FILE "./config/device.file"  
#define IP_FILE "./config/ip.file"
#define ROUTE_FILE "./config/route.file"
#define ARP_FILE "./config/arp_table.file"


//表项大小
#define MAX_DEVICE 10
#define MAX_ARP_SIZE 10
#define MAX_ROUTE_INFO 10

struct device_item {    //设备表
    char interface[14]; //端口名
    char mac[6];        //端口的 MAC地址
} device[MAX_DEVICE];
int n_dev;

struct ip_item {        //IP表
	char interface[14]; //端口名
	char ip[4];         //端口的 IP地址
} ip_table[MAX_DEVICE];
int n_ip;

struct arp_table_item { //ARP表
    char ip[4];         //IP地址
    char mac[6];        //目的MAC地址
} arp_table[MAX_ARP_SIZE];
int n_arp;

struct route_item {     //路由表
    char dst_ip[4];     //目的IP
    char gateway[4];    //默认网关
    char netmask[4];    //子网掩码
    char interface[14]; //下一条端口
} route_info[MAX_ROUTE_INFO]; 
int n_route;

int index_ip, index_arp, index_route, index_interface;
FILE *fp;


char recv_buf[128];
char send_icmp_buf[98];
char recv_icmp_buf[98];

char tmp_mac_addr[18], tmp_ip_addr[14];

int sock_raw_fd;
struct sockaddr_ll saddr_11;        //物理地址结构
struct ifreq ifr;                   //.网络(网卡)接口数据结构

void init_file();

void StoMac(char *src, char *dst);  //把文件中读入的 MAC地址 转化为 6字节MAC
void StoIP(char *src, char *dst);   //把文件中读入的 IP地址  转化为 4字节IP


int ARP_index(char *ip);             //查询 IP  是否在 ARP表中               
int IP_index(char *ip);              //查询 IP  是否为 本机 IP
int MAC_index(char *mac);            //查询 MAC 是否为 本机 MAC
int find_route(char *dst);          //查询 IP  是否在路由表中有规则
int Interface_index_of_MAC(char *interface); //查找制定端口的 MAC 地址

uint16_t check_sum(uint16_t *buf, int len); //校验和算法
void recv_packet();                 //监听收包程序
void err_exit(const char *err_msg); //错误退出
