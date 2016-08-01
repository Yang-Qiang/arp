#include<stdio.h>
#include<pcap.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<net/if.h>
#include<sys/stat.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<string.h>
#include<unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h> /* for strncpy */

char* getMyIP(){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM,0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name,"eth0",IFNAMSIZ-1);
	ioctl(fd,SIOCGIFADDR, &ifr);
	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}
char* getMyMAc(){
	FILE *fp;
	char buf[256];
	fp = popen(" ifconfig | grep 'HWaddr' | awk '{ print $5}'","r");

	if( fp == NULL)
	{
		perror("error");
		exit(0);
	}
	fgets(buf, 18, fp);

	return buf;
}
char* getGatewayIP(){
	FILE *fp;
        char buf[256];
        fp = popen(" route | grep 'default' | awk '{print $2}'","r");

        if( fp == NULL)
        {
                perror("error");
                exit(0);
        }
        fgets(buf, 14, fp);

        return buf;
}

int main(int argc, char* argv[])
{
 char victmIP[256];
 printf("%s\n", getMyIP());
 printf("%s\n", getMyMAc());
 printf("%s\n",getGatewayIP());
 strcpy(victmIP,argv[1]);
 printf("%s\n",victmIP);
 return 0;
}
