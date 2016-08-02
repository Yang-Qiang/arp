#include <net/ethernet.h>
#include <stdlib.h>
#include<inttypes.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
#include <string.h>
#include <sys/types.h>

#define Mac_length 6

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
char* getMyMac(){
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

char* set_packet(const char* senderIP,const char* recieverIP,char* senderMac){
	char *packet,*Mactok;
	char *Mac;
	char* Temp[Mac_length];
	struct ether_header *ep;
	struct ip *iph;
	struct tcphdr *tcp;
	unsigned short e_type;
	int i=0;
	packet = NULL;
	ep = (struct ether_header *)packet;
	memcpy(ep->ether_shost,string_To_Mac(senderMac),Mac_length);
	printf("SRC MAP= %x-%x-%x-%x-%x-%x\n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);

	return packet;
}
__u_char* string_To_Mac(char* Mac_addr){
	__u_char* converted = (__u_char *)malloc(Mac_length);
	sscanf(Mac_addr,"%x:%x:%x:%x:%x:%x",&converted[0],&converted[1],&converted[2],&converted[3],&converted[4],&converted[5]);
	return converted;
	}
int main(int argc, char* argv[])
{
 char victmIP[256],MyIP[256],MyMac[256],GateIP[256];
 int i;
 char* tok;
 strcpy(MyIP,getMyIP());
 strcpy(MyMac,getMyMac());
 strcpy(GateIP,getGatewayIP());

 printf("%s\n",MyIP);
 printf("%s\n",GateIP);
 printf("%s\n",MyMac);
 strcpy(victmIP,argv[1]);
 printf("%s\n",victmIP);
 tok=strtok(getMyMac(),":");
 printf("%s\n",tok);
 while(tok = strtok(NULL,":")){
	printf("%s\n",tok);
}
 set_packet(MyIP,victmIP,MyMac);
 return 0;
}
