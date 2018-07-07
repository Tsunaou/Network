#include "head.h"

double Cal_Time_Costs(struct timeval begin, struct timeval end)	//计算送begin到end历时多久
{
    long sec = end.tv_sec - begin.tv_sec;
    long usec = end.tv_usec - begin.tv_usec;
    double result = sec * 1000 + (double)(usec + 500) / 1000;

    return result;
}

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


