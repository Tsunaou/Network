#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048	//缓冲区长度

void IP_Parsing (char *ip_head);
void ARP_Parsing (char *arp_head);


int main(int argc,char* argv[]){
	int sock_fd;//要设置的套接字描述符
	int proto;	//Protocol 协议
	int n_read;	//接收到的字节数
	char buffer[BUFFER_MAX];//接收数据缓冲区。
	char *eth_head;	//以太帧头
	char *data_head;//各种协议..
	char *tcp_head;
	char *udp_head;
	char *icmp_head;
	unsigned char *p;
	unsigned char *type;
	/*
	 *int socket(int domain, int type, int protocol);
	 *函数说明：
		domain：协议域，又称协议族（family）。协议族决定了socket的地址类型
		type：指定Socket类型。
		protocol：指定协议
			如果调用成功就返回新创建的套接字的描述符
			如果失败就返回INVALID_SOCKET（Linux下失败返回-1）
	*/
	
	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
	{
		printf("error create raw socket\n");
		return -1; 
	}
	while(1)
	{
		/*ssize_t recvfrom(int sockfd,void *buf,size_t len,unsigned int flags, struct sockaddr *from,socket_t *fromlen); 
		 *函数说明:
		 recvfrom()用来接收远程主机经指定的socket传来的数据,
		 并把数据传到由参数buf指向的内存空间,参数len为可接收数据的最大长度.
		 参数flags一般设0,其他数值定义参考recv().
		 参数from用来指定欲传送的网络地址,结构sockaddr请参考bind()函数.
		 参数fromlen为sockaddr的结构长度.
		返回值:成功则返回接收到的字符数,失败返回-1
		*/
		n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read < 42)
		{
			printf("error when recv msg \n");
			return -1; 
		}
		eth_head = buffer;
		p = eth_head;//指向以太帧头部
		printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x==> %.2x:%02x:%02x:%02x:%02x:%02x\n",
			p[6],p[7],p[8],p[9],p[10],p[11],
			p[0],p[1],p[2],p[3],p[4],p[5]);
		
		data_head = eth_head+14;//偏移量14Bytes，指向数据报
		type = eth_head + 12;
		if(type[0] == 0x08)
		{
			switch(type[1])
			{
				case 0x00:
					printf("The type is IP . Now I'll parsing it:\n");
					IP_Parsing(data_head);
					break;
				case 0x06:
					printf("The type is ARP . Now I'll parsing it:\n");
					ARP_Parsing(data_head);
					printf("APR Parsing Termination\n");
					break;
				case 0x35:
					printf("The type is RARP . Now I'll parsing it:\n");
					ARP_Parsing(data_head);
					printf("RAPR Parsing Termination\n");
					break;
				default:
				{
					printf("Invalied type !\n");
					return -1;
				}
			}
		}
		else
		{
			printf("Receive data error, Invalied type !\n");
			return -1;
		}
		
	}
	return -1;
	
}

void IP_Parsing (char *ip_head)
{
	unsigned char *p = ip_head+12;//偏移量26Bytes，指向32位源IP地址和32位目的IP地址
	printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",
			p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
	int proto = (ip_head + 9)[0];	
	p = ip_head +12;//偏移量38Bytes，指向协议类型？
	printf("Protocol:");
	
	switch(proto){
		case IPPROTO_ICMP:printf("icmp\n");break;
		case IPPROTO_IGMP:printf("igmp\n");break;
		case IPPROTO_IPIP:printf("ipip\n");break;
		case IPPROTO_TCP:printf("tcp\n");break;
		case IPPROTO_UDP:printf("udp\n");break;
		default:printf("Pls query yourself\n");
	}

}

void ARP_Parsing (char *arp_head)
{
	unsigned char * HTYPE = arp_head;		//Hardware type
	unsigned char * PTYPE = arp_head + 2;	//Protocol type
	unsigned char * HLEN  = arp_head + 4;	//Hardware address length 
	unsigned char * PLEN  = arp_head + 5;	//Protocol address length 
	unsigned char * OPER  = arp_head + 6;	//Operation
	unsigned char * SHA   = arp_head + 8;	//Sender hardware address
	unsigned char * SPA   = arp_head + 14;	//Sender protocol address
	unsigned char * THA   = arp_head + 18;	//Target hardware address
	unsigned char * TPA   = arp_head + 24;	//Target protocol address

	int tmp = 0;

	//Hardware type
	tmp = (HTYPE[0]<<8) | HTYPE[1] ;
	printf("Hardware type is : %x\n", tmp);

	//Protocol type
	tmp = (PTYPE[0]<<8) | PTYPE[1] ;
	printf("Protocol type is : %x\n", tmp);
	
	//Hardware address length 
	tmp = HLEN[0];
	printf("Hardware address length is : %x\n", tmp);

	//Protocol address length 
	tmp = PLEN[0];
	printf("Protocol address length is : %x\n", tmp);

	//Operation
	tmp = (OPER[0]<<8) | OPER[1] ;
	switch(tmp)
	{
		case 1:
			printf("Operation is ARP request\n");
			break;
		case 2:
			printf("Operation is ARP reply\n");
			break;
		default:
			printf("Error in ARP operation!\n");
			return;
	}
	
	//Sender hardware address ==> Target hardware address
	printf("hardware address: %.2x:%02x:%02x:%02x:%02x:%02x==>%.2x:%02x:%02x:%02x:%02x:%02x\n",
			SHA[0],SHA[1],SHA[2],SHA[3],SHA[4],SHA[5],
			THA[0],THA[1],THA[2],THA[3],THA[4],THA[5]);
	//Sender protocol address ==> Target protocol address
	printf("protocol Address:%d.%d.%d.%d==>%d.%d.%d.%d\n",
			SPA[0],SPA[1],SPA[2],SPA[3],
			TPA[0],TPA[1],TPA[2],TPA[3]);

	return;
}
