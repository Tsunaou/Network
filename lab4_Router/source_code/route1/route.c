#include "head.h"

void init_device(); //初始化设备表
void init_ip();		//初始化IP表
void init_route(); 	//初始化路由表
void init_arp();	//初始化ARP表
void send_icmp(char *interface); //向端口发送ICMP数据报
void Get_ARP_Index(char *dst_ip);  //获取ARP索引
void send_icmp_reply(); //路由器被ping，直接转发回去
void send_icmp_forward(); //转发icmp报文
void Solve_icmp(); //处理icmp报文
void Solve_ip(); //处理ip报文
void recv_packet(); //收包函数	
void init() 	//初始化函数



void init_device() 
{
    if((fp=fopen(DEVICE_FILE, "r"))==NULL) {
        printf("error: open device.file");
        return ;
    }
    while((fscanf(fp, "%s%s", device[n_dev].interface, tmp_mac_addr)) != EOF) 
    {
        StoMac(tmp_mac_addr, device[n_dev].mac);
        memset(tmp_mac_addr, 0, 18);
        n_dev++;
    }
    fclose(fp);
}

void init_ip() 
{
    if((fp=fopen(IP_FILE, "r"))==NULL) 
    {
        printf("error: open ip.file");
        return ;
    }
    while((fscanf(fp, "%s%s", ip_table[n_ip].interface, tmp_ip_addr)) != EOF) 
    {
        StoIP(tmp_ip_addr, ip_table[n_ip].ip);
        memset(tmp_ip_addr, 0, 14);
        n_ip++;
    }
    fclose(fp);
}

void init_route() 
{
    if((fp=fopen(ROUTE_FILE, "r"))==NULL){
        printf("Can't open file . \n");
        return ;
    }
    while((fscanf(fp, "%s", tmp_ip_addr)) != EOF) 
    {
        StoIP(tmp_ip_addr, route_info[n_route].dst_ip);
        memset(tmp_ip_addr, 0, 16);
        fscanf(fp, "%s", tmp_ip_addr);
        StoIP(tmp_ip_addr, route_info[n_route].gateway);
        memset(tmp_ip_addr, 0, 16);
        fscanf(fp, "%s", tmp_ip_addr);
        StoIP(tmp_ip_addr, route_info[n_route].netmask);
        memset(tmp_ip_addr, 0, 16);
        fscanf(fp, "%s", route_info[n_route++].interface);
    }
    fclose(fp);
}

void init_arp()
{
    n_arp = 0;
    if((fp=fopen(ARP_FILE, "r"))==NULL){
        printf("Can't open file . \n");
        return ;
    }
    while((fscanf(fp, "%s", tmp_ip_addr)) != EOF) 
    {
        StoIP(tmp_ip_addr, arp_table[n_arp].ip);
        memset(tmp_ip_addr, 0, 16);
        fscanf(fp, "%s", tmp_mac_addr);
        StoMac(tmp_mac_addr, arp_table[n_arp].mac);
        memset(tmp_mac_addr, 0, 18);
        n_arp++;
    }
    fclose(fp);    
}

void init_file() 
{
    init_device();
    init_ip();
    init_route();
    init_arp();
}


void send_icmp(char *interface) //向端口发送ICMP数据报
{

    struct sockaddr_ll saddr_ll;    //初始化链路层地址和网卡索引名 
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    memcpy(ifr.ifr_name, interface, sizeof(interface) );
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1) //获取接口索引
    {
        err_exit("ioctl() get ifindex");
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex; //补充链路层信息
    saddr_ll.sll_family = PF_PACKET;

    int ret_len = sendto(sock_raw_fd, send_icmp_buf, sizeof(send_icmp_buf), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
    if ( ret_len > 0) 
    {
        printf("send icmp ok!!!\n");
    }

}


void Get_ARP_Index(char *dst_ip)  //获取ARP索引
{
    index_arp = ARP_index(dst_ip);
}

void send_icmp_reply() //路由器被ping，直接转发回去
{
  
    char *p = send_icmp_buf;
    char *q = recv_icmp_buf;
    bzero(p, sizeof(send_icmp_buf) );
    memcpy(p, q, sizeof(recv_icmp_buf) );

    char * send_dst_mac     = send_icmp_buf;      //0
    char * send_src_mac     = send_icmp_buf + 6;  //6
    char * send_ip_head     = send_icmp_buf + 14; //14
    char * send_ip_ttl      = send_ip_head  + 8; 
    char * send_ip_cksum    = send_ip_head  + 10;
    char * send_ip_src_ip   = send_ip_head  + 12;
    char * send_ip_dst_ip   = send_ip_head  + 16;

    char * recv_dst_mac     = recv_icmp_buf;      //0
    char * recv_src_mac     = recv_icmp_buf + 6;  //6
    char * recv_ip_head     = recv_icmp_buf + 14; //14
    char * recv_ip_src_ip   = recv_ip_head  + 12;
    char * recv_ip_dst_ip   = recv_ip_head  + 16;
   

    memcpy( send_src_mac, device[index_ip].mac, 6 );
    memcpy( send_dst_mac, recv_src_mac, 6);


    *(uint16_t*)(send_ip_ttl) = 0x0140;
    memcpy(send_ip_src_ip, recv_ip_dst_ip, 4);
    memcpy(send_ip_dst_ip, recv_ip_src_ip, 4);
    bzero(send_ip_cksum, 2);
    *(uint16_t*)(send_ip_cksum) = check_sum((uint16_t*)(send_ip_head), 5 << 2);
    // icmp header
    char * send_icmp_head    = send_ip_head  + 20;
    char * recv_icmp_head    = send_ip_head  + 20;
    char * send_icmp_cksum   = send_icmp_head+ 2;

    bzero(send_icmp_head, 4);
    *(uint16_t*)(send_icmp_cksum) = check_sum((uint16_t*)(send_icmp_head), 64/2);

    send_icmp( ip_table[index_ip].interface );
}

void send_icmp_forward() //转发icmp报文
{
    char *p = send_icmp_buf;
    char *q = recv_icmp_buf;
    bzero(p, sizeof(send_icmp_buf) );
    memcpy(p, q, sizeof(recv_icmp_buf) );

    char * send_dst_mac     = send_icmp_buf;      //0
    char * send_src_mac     = send_icmp_buf + 6;  //6
    char * send_ip_head     = send_icmp_buf + 14; //14
    char * send_ip_ttl      = send_ip_head  + 8; 
    char * send_ip_cksum    = send_ip_head  + 10; 

    memcpy(send_dst_mac, arp_table[index_arp].mac, 6);      //转发的时候把以太网帧包头的MAC地址改一下
    memcpy(send_src_mac, device[index_interface].mac, 6);   //
    
    *(uint8_t*)(send_ip_ttl) = *(uint8_t*)(send_ip_ttl) - 1;
    bzero(send_ip_cksum, 2);
    *(uint16_t*)(send_ip_cksum) = check_sum((uint16_t*)(send_ip_head), 5 << 2);

    send_icmp( route_info[index_route].interface );
}

void Solve_icmp() //处理icmp报文
{
    char *p = recv_icmp_buf;
    bzero(recv_icmp_buf, sizeof(recv_icmp_buf) );
    memcpy(recv_icmp_buf, recv_buf, sizeof(recv_icmp_buf));

    char * ip_head = recv_icmp_buf + 14;
    char * ip_dst_ip = ip_head +16;

    if ( ( index_ip = IP_index(ip_dst_ip) ) != -1 ) //该包目的IP是路由器端口，那就直接回去
    {
        send_icmp_reply();
    } 
    else if ( ( index_route = find_route(ip_dst_ip) ) != -1 )   //转发表中有目的ip的路由规则（用子网掩码&一下）
    {
        index_interface = Interface_index_of_MAC(route_info[index_route].interface); //查找该端口对应的默认网关
        if ( *(int*)(route_info[index_route].gateway) == 0 )    //没有默认网关的话
        {
            Get_ARP_Index(ip_dst_ip);                                 //查询ARP缓存
        } 
        else                                                    //有默认网关的话
        {
            Get_ARP_Index(route_info[index_route].gateway);           //发送ARP缓存
        }
        send_icmp_forward();//Get_ARP_Index后，理应能在arp表中找到转发的mac地址，转发
    }
}

void Solve_ip() //处理ip报文
{
    char *ip_head = recv_buf + 14;
    int proto = (ip_head + 9)[0];
    
}

void recv_packet() 
{
    printf("recvfrom start！\n");
    
    while(1) 
    {

        if ( recvfrom(sock_raw_fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL ) <= 0) 
        {
            printf("recvfrom error\n");
            continue;
        }
        char *eth_head;
        unsigned char *type;

        eth_head = recv_buf;
        type = eth_head + 12;
        if(type[0] == 0x08)
        {
            switch(type[1])
            {
                case 0x00:  
                    if( MAC_index(recv_buf) == -1 ) //不是发往本机的（端口MAC没有找到）
                    {
                        continue;
                    }
                    Solve_ip(); 
                    break;
                default:
                {
                    printf("Invalied type !\n");
                }
            }
        }
    }
}

void init() 
{
    //创建一个AF_PACKET套接字
    //1）domain为AF_PACKET.
    // 2) SOCK_RAW------自己构造以太头
    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) 
    {
        err_exit("socket()");
    }
    init_file();
}

int main(void)
{
    init();
    recv_packet();

    return 0;
}
