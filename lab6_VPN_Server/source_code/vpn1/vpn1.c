#include "head.h"

void init_device();     //初始化设备表
void init_ip();		    //初始化IP表
void init_route(); 	    //初始化路由表
void init_arp();	    //初始化ARP表
void init_file();       //初始化文件
void init(); 	        //初始化函数
void init_sockets();    //初始化套接字
void test_init_route(); //输出路由表
void recv_packet();     //收包
void Solve_ip();        //处理ip报文
void Unpack();			//解封包,并转发
void Repack();			//给包加上IP包头转发
void VPN_Send();		//给加上IP头的包转发


void test_init_route() 
{
	printf("------ test init route n_route: %d ------\n", n_route);
	int i;
	for(i=0; i<n_route; i++)
    {
		Print_IP(route_info[i].dst_ip);
		Print_IP(route_info[i].gateway);
		Print_IP(route_info[i].netmask);
		printf("%s\n", route_info[i].interface);
	}
	printf("------ test init route n_route: %d ------\n", n_route);
}

void init_device() 
{
    if((fp = fopen(DEVICE_FILE, "r")) == NULL)
    {
        printf("error: open device.file");
        return ;
    }
    while((fscanf(fp, "%s%s", device[n_dev].interface, tmp_mac_addr)) != EOF) 
    {
        StoMac(tmp_mac_addr, device[n_dev].mac);
        printf("%s: ", device[n_dev].interface);
        Print_Mac(device[n_dev].mac);
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
        printf("%s: ", ip_table[n_ip].interface);
        Print_IP(ip_table[n_ip].ip);
        memset(tmp_ip_addr, 0, 14);
        n_ip++;
    }
    fclose(fp);
}

void init_route() 
{
    if((fp=fopen(ROUTE_FILE, "r"))==NULL)
    {
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
    test_init_route();
}

void init_arp()
{
    n_arp = 0;
    if((fp=fopen(ARP_FILE, "r"))==NULL)
    {
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

void init_sockets()
{
    //收包套接字
    if((re_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    {
        printf("Error Creating Recving Raw Socket\n");
		exit(1);
    }
    printf("Successfully Creating Recving Raw Socket\n");

    //转发包套接字
    if((se_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IPIP)) < 0)
    {
        printf("Error Creating Sending Raw Socket\n");
		exit(1); 
    }

    printf("Successfully Creating Sending Raw Socket\n");
}

void init()
{
    init_file();
    init_sockets();
}

void Unpack()   //
{
    printf("------ Unpack ip ------\n");
    printf("------ Ready to leave vpn ------\n");

    char *ip_head = recv_buf + 14;
    char *dst_ip = ip_head + 16;

    int index = find_route(dst_ip);
    printf("Next IP: "); Print_IP(route_info[index].gateway);

    char *real_ip_head = ip_head + sizeof(struct iphdr);
    //接下来封装一下以太帧头我想就可以了
    int real_ip_lenth = n_read - 14 - sizeof(struct iphdr); //原来ip数据报长度
    int lenth = sizeof(struct ethhdr) + real_ip_lenth;
    char packet[lenth];     
    struct ethhdr * ethhdr 	 =(struct ethhdr *)(packet);    

    memcpy(packet+sizeof(struct ethhdr), real_ip_head, real_ip_lenth);  //复制过来
    ethhdr->h_proto=htons(ETH_P_IP);
    memcpy(ethhdr->h_dest,arp_table[0].mac,6);
    memcpy(ethhdr->h_source,device[0].mac,6);
    
    struct sockaddr_ll saddr_ll;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    memcpy(ifr.ifr_name, device[0].interface, strlen(device[0].interface));
    if (ioctl(re_sock_fd, SIOCGIFINDEX, &ifr) == -1) {
        err_exit("ioctl() get ifindex");
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;

    int ret_len = sendto(re_sock_fd, packet, lenth, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
    if (ret_len > 0) 
    {
        printf("Unpack and resend ok!!!\n");
        //recv_packet();
    }
    memset(recv_buf, 0 , BUFSIZE);      //清零看看

    printf("------ Unpack ip ------\n");    
}

void VPN_Send(char* buffer, int buffer_len, int index)//buffer：旧包的IP头起始位置 ,buffer_len，旧包IP数据报的长度
{
    struct sockaddr_in sock_in;
    sock_in.sin_family = AF_INET;
    char dstip[16];
    strcpy(dstip, "172.0.0.2");
    sock_in.sin_addr.s_addr = inet_addr(dstip);
    //Sendto
    int n_send;
    if((n_send = sendto(se_sock_fd, buffer, buffer_len, 0,(struct sockaddr *)&sock_in, sizeof(struct sockaddr))) < 0){
    	printf("sendto error!");
    	exit(-1);
    }
    else{
    	printf("send %d OK\n",n_send);
    }
}

void Repack()   //VPN转发
{
    printf("------ Repack ip ------\n");
    printf("------ Ready to exit vpn ------\n");
    
    char *ip_head = recv_buf + 14;
    char *dst_ip = ip_head + 16;

    int index = find_route(dst_ip);
    printf("Next IP: "); Print_IP(route_info[index].gateway);

    VPN_Send(ip_head, n_read-14, index);

    printf("------ Repack ip ------\n");
}

void Solve_ip() //处理ip报文
{
    printf("------ solve ip ------\n");
    
    char *ip_head = recv_buf + 14;
    char *src_ip = ip_head + 12;
    char *dst_ip = ip_head + 16;

    printf("from ip: ");    Print_IP(src_ip);
    printf("to ip: ");      Print_IP(dst_ip);
    
    int eth_no = MAC_index(recv_buf);

    switch(eth_no)
    {
        case 0:
            printf("Recving form eth0:\n");
            Repack();
            break;   
        case 1:
            printf("Recving form eth1:\n");
            Unpack();
            break;
        default:
        {
            printf("eth error!\n");
        }
    }
       
    printf("------ solve ip ------\n");
    
}

void recv_packet() 
{
    printf("Recvfrom start！\n");
    
    while(1) 
    {
        if ((n_read = recvfrom(re_sock_fd, recv_buf, BUFSIZE, 0, NULL, NULL )) <= 0) 
        {
            printf("Recvfrom error\n");
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
                    if(MAC_index(recv_buf) == -1 ) //不是发往本机的（端口MAC没有找到）
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

int main(int argc, char* argv[])
{
    init();
    recv_packet();
}