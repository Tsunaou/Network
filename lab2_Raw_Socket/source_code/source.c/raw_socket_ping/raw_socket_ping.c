#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_ether.h>



#define MAX_SIZE_OF_PACKERTS    128        //一次ping操作最多发送的数据包
#define MAX_SIZE                128        //一次发送包的最大大小
#define BUFFER_SIZE             64*1024    //缓冲区大小,64KB
#define MAX_NO_OF_PACKETS       12        //最大发包数目

typedef struct Packets_Status
{
    struct timeval begin_time;  //发送包时间
    struct timeval end_time;    //接收包时间
    bool flag;                  //是否到达标志
    int seq;                    //序列号
}Packets_Status;

Packets_Status Packets[MAX_SIZE_OF_PACKERTS];

int sock_fd = 0;    //套接字描述符
int n_Send = 0;     //发送的包数量
int n_Recv = 0;     //接收的包数量
pid_t pid_no = 0;   //进程号，用于校验

struct sockaddr_in dest_addr;   //发送目的地址
char send_buf[MAX_SIZE];    //发送包缓冲数组
char recv_buf[MAX_SIZE];    //接收包缓冲数组

unsigned short Cal_chksum(unsigned short *addr,int len);    //计算校验和
double Cal_Time_Costs(struct timeval begin, struct timeval end);    //计算收发包间隔的时间
void ICMP_Pack(struct icmp* icmphdr, int seq, int length);  //ICMP包的打包
bool ICMP_Unpack(char* buf, int len);    //ICMP包的解析
void Send_Packets();    //发包函数
void Recv_Packets();    //收包函数
void Parse_IP(struct ip* ip_hdr);   //分析包的来历（来源IP和目的IP地址）
void Init_Addr(char* argv[]);	//分析输入地址
void toStringIP(const unsigned int ip,char *stringIP);  //把 unsigned int 的 ipv4地址转化为字符串

unsigned short Cal_chksum(unsigned short *ICMP_Hdr,int size)	//计算校验和
{  
	unsigned int sum = 0;
	unsigned short *w = ICMP_Hdr;
	unsigned short answer = 0;

	while(size > 1)
	{
		sum += *w++;
		size -= 2;
	}

	if(size == 1)  
		sum += *w;  

	sum=(sum>>16)+(sum&0xffff); 
	sum=(sum>>16)+(sum&0xffff); 
    
	return (unsigned short)(~sum); 
}

double Cal_Time_Costs(struct timeval begin, struct timeval end)	//计算送begin到end历时多久
{
    long sec = end.tv_sec - begin.tv_sec;
    long usec = end.tv_usec - begin.tv_usec;
    double result = sec * 1000 + (double)(usec + 500) / 1000;

	return result;
}

void ICMP_Pack(struct icmp* ICMP_Hdr, int seq, int length)	//对ICMP头进行组装
{
    ICMP_Hdr->icmp_type = ICMP_ECHO;
    ICMP_Hdr->icmp_code = 0;
    ICMP_Hdr->icmp_cksum = 0;
    ICMP_Hdr->icmp_seq = seq;
    ICMP_Hdr->icmp_id = pid_no;
    ICMP_Hdr->icmp_cksum = Cal_chksum((unsigned short*)ICMP_Hdr, length);
}

void toStringIP(const unsigned int ip,char *stringIP)//把unsigned int型存储的ipv4地址转化成字符串
{
    unsigned int tempIP = ip;
    int i=0;
    for(; i < 3; i++)
    {
        unsigned char part= (char) tempIP;
        char temp[4];
        sprintf(temp,"%d.",part);
        strcat(stringIP,temp);
        tempIP = tempIP >> 8;
    }
    unsigned char part=(char)tempIP;
    char temp[4];
    sprintf(temp,"%d",part);
    strcat(stringIP,temp);
}


void Parse_IP(struct ip* ip_hdr)//分析该IP数据报的来历
{    
    char* stringIP = (char*)malloc(16);
    memset(stringIP,0,16+1);

    unsigned int ip = 0;
    ip = ip_hdr->ip_dst.s_addr;
    toStringIP(ip,stringIP);
    printf("\nform %s\nto ",stringIP);

    ip = ip_hdr->ip_src.s_addr;       
    memset(stringIP,0,16+1);
    toStringIP(ip,stringIP);
    printf("%s\n",stringIP);

}

bool ICMP_Unpack(char* buf, int len)
{
    struct timeval begin_time, recv_time;	//记录开始发包和收包的时间
    struct ip* ip_hdr = (struct ip *)buf;	//定义IP头
    int iphdr_len = ip_hdr->ip_hl * 4;
    struct icmp* icmp = (struct icmp*)(buf+iphdr_len);	//转到ICMP协议头
	
    len -= iphdr_len;  
    
    //判断该包是ICMP回送回答包且该包是我们发出去的
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid_no)) 
    {
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > MAX_SIZE_OF_PACKERTS))
        {
            fprintf(stderr, "ICMP packets is overflow!\n");
            return false;
        }

        Packets[icmp->icmp_seq].flag = 0;	//确认该包已经被接受
        begin_time = Packets[icmp->icmp_seq].begin_time;	//获取该包被发送的时间
        gettimeofday(&recv_time, NULL);	//获取当前时间

        double rtt = Cal_Time_Costs(begin_time, recv_time); //round trip time，记录该包从发送到回应的历时

        Parse_IP(ip_hdr);

        printf("received  ping succeed!\n");
        printf("%d bytes from %s: icmp_seq=%u ttl=%d rtt=%f ms\n",
            len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);  

        return true;      
    }
    else
    {
        fprintf(stderr, "The ICMP Packet is not sended by us\n");
        return false;
    }
    
}

void Send_Packets()
{
    memset(send_buf, 0, sizeof(send_buf));

    if(n_Send < MAX_NO_OF_PACKETS)
    {
        //printf("send is %d\n",n_Send);
        gettimeofday(&(Packets[n_Send].begin_time), NULL);
        Packets[n_Send].flag = 1; //将该标记为设置为该包已发送

        ICMP_Pack((struct icmp*)send_buf, n_Send, 64); //封装icmp包
        if(sendto(sock_fd, send_buf, 64, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0)
        {
            fprintf(stderr, "send icmp packet fail!\n");
            return;
        }
        printf("send ping succeed!");
        n_Send++; //记录发出ping包的数量
        sleep(0.1);

    }
}



void Recv_Packets()
{
    //printf("Recv is %d\n",n_Recv);
    struct timeval tv;
    tv.tv_usec = 200;  //设置select函数的超时时间为200us
    tv.tv_sec = 0;
    fd_set read_fd;
    memset(recv_buf, 0 ,sizeof(recv_buf));
    if(n_Recv < MAX_NO_OF_PACKETS)
    {
        //printf("Recv is %d\n",n_Recv);
        FD_ZERO(&read_fd);
        FD_SET(sock_fd, &read_fd);

        int ret = select(sock_fd+1, &read_fd, NULL, NULL, &tv);
        if(ret > 0)
        {
            int size = recv(sock_fd, recv_buf, sizeof(recv_buf), 0);
            if(errno == EINTR)
            {
                fprintf(stderr,"recv data fail!\n");
                return;
            }

            if(ICMP_Unpack(recv_buf, size) == false)  //不是属于自己的icmp包，丢弃不处理
            {
                return;
            }
            n_Recv++; //接收包计数
        }

    }
}

void Init_Addr(char* argv[])
{
	//初始化目的地址
	bzero(&dest_addr,sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
	
    unsigned int in_addr = inet_addr(argv[1]);
	//解析用户输入的地址
    if(in_addr == INADDR_NONE)  //判断用户输入的是否为IP地址还是域名
    {
        struct hostent *host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            printf("Invalid Domain Name Server Address!\n");
            exit(-1); 
        }
        else
        {
            memcpy((char*)&dest_addr.sin_addr, host->h_addr, host->h_length);
        }
    }
    else//输入的是IP地址
    {
        //得到主机IP地址（一开始以为会是192.168.2.1，后来发现是ubuntu的地址）
		char host[100] = {0};
        if(gethostname(host,sizeof(host)) < 0)
        {
            printf("Invalid IP Address!\n");
        }
 
        struct hostent *hp;
        if ((hp=gethostbyname(host)) == NULL)
        {
            printf("Invalid IP Address!\n");
        }
 
        int i = 0;
        while(hp->h_addr_list[i] != NULL)
        {
                printf("Hostname: %s\n",hp->h_name);
                printf("Host Ip Address is: %s\n\n",inet_ntoa(*(struct in_addr*)hp->h_addr_list[i]));
                i++;
        }
        memcpy((char*)&dest_addr.sin_addr, &in_addr, sizeof(in_addr));
    }

    in_addr = dest_addr.sin_addr.s_addr;
}



int main(int argc, char* argv[])
{

    if(argc < 2)    //判断参数个数
    {
        printf("The format is error!\n");
        printf("You can try as the format : sudo ./ping 192.168.3.2\n");
        return -1; 
    }

    sock_fd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);	//创建类型为IPPROTO_ICMP的套接字描述符
    if(sock_fd < 0)
    {
        printf("Error Create Raw Socket\n");
		return -1; 
    }

	Init_Addr(argv);	//分析main函数的输入地址是否有误
	
    printf("PING %s (%s) 56(84) bytes of data.\n\n",argv[1],argv[1]);
    
    struct timeval start,end;	//记录ping开始和ping结束的时间
    gettimeofday(&start, NULL);

	pid_no = getpid();//获取main的进程id,用于设置ICMP的标志符

    while(n_Send < MAX_NO_OF_PACKETS && n_Recv < MAX_NO_OF_PACKETS)	//使得ping发送 MAX_NO_OF_PACKETS 数目的包
    {
        Send_Packets();
        Recv_Packets();
        printf("\n"); 
    }   
    
    gettimeofday(&end, NULL);
	//对一次ping的结果进行输出
    printf("This ping We send %d packets and receive %d packets, it takes a time of %f ms\n",n_Send,n_Recv,Cal_Time_Costs(start,end));

    close(sock_fd);

    return 0;

}



