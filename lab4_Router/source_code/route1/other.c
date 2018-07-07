#include "head.h"

void err_exit(const char *err_msg) 
{
    perror(err_msg);
    exit(1);
}

uint8_t MyStoi(char *p, int n, int base) 
{
    int res = 0, i;
    for(i=0; i<n; i++) 
    {
        res *= base;
        if(p[i]>='a') 
        {
            res += p[i] - 'a' + 10;
        } 
        else 
        {
            res += p[i] - '0';	
        }
    }
    return (uint8_t)res;
}


void StoMac(char *src, char *dst) 
{
    char sep = ':';;
    int base = 16;
    int old_i = 0, i;
    for(i=0; src[i]; i++) {
        if(*(src+i) == sep) {
            *(uint8_t*)(dst++) = MyStoi(src+old_i, i - old_i, base);
            old_i = i + 1;
        }
    }   
    *(uint8_t*)(dst) = MyStoi(src+old_i, i - old_i, base);
}

void StoIP(char *src, char *dst) 
{
    char sep = '.';
    int base = 10;
    int old_i = 0, i;
    for(i=0; src[i]; i++) {
        if(*(src+i) == sep) {
            *(uint8_t*)(dst++) = MyStoi(src+old_i, i - old_i, base);
            old_i = i + 1;
        }
    }   
    *(uint8_t*)(dst) = MyStoi(src+old_i, i - old_i, base);
}

int ARP_index(char *ip) 
{
    int res = -1, i;
    for(i=0; i<n_arp; i++) 
    {
        if( memcmp(ip, arp_table[i].ip, 4) == 0 ) 
        {
            res = i;
            break;
        }
    }
    return res;
}

int IP_index(char *ip) 
{
    int res = -1, i;
    for(i=0; i<n_ip; i++) 
    {
        if( memcmp(ip, ip_table[i].ip, 4) == 0 )
        {
            res = i;
            break;
        }
    }
    return res;
}


int MAC_index(char *mac)//查询是否是设备的MAC地址  
{
    int res = -1, i;
    for(i=0; i<n_dev; i++) {
        if( memcmp(mac, device[i].mac, 6) == 0 ) {
            res = i;
            break;
        }
    }
    return res;
}

int Interface_index_of_MAC(char *interface) //查找端口的MAC地址 
{
    int res = -1, i;
    for(i=0; i<n_dev; i++) 
    {
        if( memcmp(interface, device[i].interface, 14) == 0 ) 
        {
            res = i;
            break;
        }
    }
    return res;
}

int find_route(char *dst) 
{
    int res = -1, i;
    for(i=0; i<n_route; i++) 
    {
        if ( ( *(int*)(dst) & *(int*)(route_info[i].netmask) ) == *(int*)route_info[i].dst_ip ) 
        {
            res = i;
            break;
        }
    }
    return res;
}


uint16_t check_sum(uint16_t *buf, int len) 
{
    uint32_t res = 0;
    while(len > 1) 
    {
          res += *buf++;
          len -= 2;
    }
    if(len == 1) 
    {
        res += *(uint8_t*)buf;
    }
    while(res >> 16) 
    {
          res = (res >> 16) + (res & 0xffff);
    }
    return ~res;
}

