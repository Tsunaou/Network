#include "head.h"

void send_icmp(char* src_mac, char *dst_mac, char* src_ip, char* dst_ip) 
{
    char *p = send_icmp_buf;
    memset(p, 0, sizeof(send_icmp_buf));

    struct ethhdr * ethhdr 	 =(struct ethhdr *)(send_icmp_buf);
    struct iphdr * ip_hdr    =(struct iphdr*)(send_icmp_buf+sizeof(struct ethhdr));
    struct icmphdr *icmp_hdr =(struct icmphdr *)(send_icmp_buf+sizeof(struct ethhdr)+20);
    
    ethhdr->h_proto=htons(ETH_P_IP);

    memcpy(ethhdr->h_dest,dst_mac,6);
    memcpy(ethhdr->h_source,src_mac,6);

    char * send_dst_mac     = send_icmp_buf;      //0
    char * send_src_mac     = send_icmp_buf + 6;  //6
    char * send_src_type    = send_icmp_buf + 12; //12    
    char * send_ip_head     = send_icmp_buf + 14; //14
    char * send_ip_ttl      = send_ip_head  + 8; 
    char * send_ip_cksum    = send_ip_head  + 10;
    char * send_ip_src_ip   = send_ip_head  + 12;
    char * send_ip_dst_ip   = send_ip_head  + 16;

    // ip header
    *(uint32_t*)(send_ip_head) = 0x54000045;
    *(uint16_t*)(send_ip_head+4) = 0x0100;
    *(uint16_t*)(send_ip_head+6) = 0x0040;
    *(uint16_t*)(send_ip_ttl) = 0x0140;

    memcpy(send_ip_src_ip, src_ip, 4);
    memcpy(send_ip_dst_ip, dst_ip, 4);

    *(uint16_t*)(send_ip_cksum) = check_sum((uint16_t*)(send_ip_head), 5 << 2);
    
    // icmp header
    char * send_icmp_head    = send_ip_head   + 20;
    char * send_icmp_type    = send_icmp_head;
    char * send_icmp_cksum   = send_icmp_head + 2;    
    char * send_icmp_code    = send_icmp_head + 4;
    char * send_icmp_seq     = send_icmp_head + 6;
    char * send_icmp_ots     = send_icmp_head + 8;
    
    *(uint8_t*)(send_icmp_type) = 0x08;
    *(uint16_t*)(send_icmp_code) = my_pid;
    *(uint16_t*)(send_icmp_seq) = ++n_Send;
    gettimeofday( (struct timeval *)(send_icmp_ots), NULL);
    *(uint16_t*)(send_icmp_cksum) = check_sum((uint16_t*)(send_icmp_head), 64/2);

    struct sockaddr_ll saddr_ll;
    bzero(&saddr_ll, sizeof(struct sockaddr_ll));
    memcpy(ifr.ifr_name, device[0].interface, strlen(device[0].interface));
    if (ioctl(sock_raw_fd, SIOCGIFINDEX, &ifr) == -1) {
        err_exit("ioctl() get ifindex");
    }
    saddr_ll.sll_ifindex = ifr.ifr_ifindex;
    saddr_ll.sll_family = PF_PACKET;

    ret_len = sendto(sock_raw_fd, send_icmp_buf, 98, 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
    if ( ret_len > 0) 
    {
        printf("sendto() icmp ok!!!\n");
        //recv_packet();
    }

}

void init_device()
{
    if((fp = fopen(DEVICE_FILE , "r")) == NULL)
    {
        printf("Error while device init\n");
    }
    
    while((fscanf(fp, "%s%s", device[n_ip].interface, tmp_mac_addr)) != EOF)
    {
        StoMac(tmp_mac_addr, device[n_dev].mac);
        memset(tmp_mac_addr, 0, 18);
        n_dev++;
    }

    fclose(fp);
}

void init_ip()
{
    if((fp = fopen(IP_FILE , "r")) == NULL)
    {
        printf("Error while ip init\n");
    }
    
    while((fscanf(fp, "%s%s", ip_table[n_ip].interface, tmp_ip_addr)) != EOF)
    {
        StoIP(tmp_ip_addr, ip_table[n_ip].ip);
        memset(tmp_ip_addr, 0, 14);
        n_ip++;
    }

    fclose(fp);
}

void init_default_gateway()
{
    if((fp = fopen(DEFAULT_GATEWAY_FILE , "r")) == NULL)
    {
        printf("Error while gw init\n");
    }
    
    fscanf(fp, "%s", tmp_ip_addr);
    StoIP(tmp_ip_addr, gateway);
    memset(tmp_ip_addr, 0, 14);

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
    init_default_gateway();
    init_arp();    
}

void init() {
    if ((sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        err_exit("socket()");
    }
    init_file();
    n_Send = 0;     //发送的包数量
    n_Recv = 0;     //接收的包数量
    my_pid = getpid();
}


int main(int argc, char* argv[])
{

    init();
  
    char dst_ip[4];

    StoIP(argv[1], dst_ip);

    printf("PING %s (%s) 56(84) bytes of data.\n\n",argv[1],argv[1]);
    
    struct timeval start,end;	//记录ping开始和ping结束的时间
    gettimeofday(&start, NULL);

    int i;
    for(i=0;i<MAX_NO_OF_PACKETS;i++)
    {
        send_icmp(device[0].mac, arp_table[0].mac, ip_table[0].ip, dst_ip);
        sleep(1);
    }

    gettimeofday(&end, NULL);
    printf("it takes a time of %f ms\n",Cal_Time_Costs(start,end));

    return 0;
}
