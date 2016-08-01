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

char* set_packet(const char* senderIP,const char* recieverIP, const char* senderMac){
	char *packet,*Mactok;
	char *Mac;
	struct ehther_header *ep;
	struct ip *iph;
	struct tcphdr *tcp;
	unsigned short e_type;
	int i=0;
	packet = NULL;
	ep = (struct ether_header *)packet;
	strcpy(Mac,senderMac);
	Mactok[0]=strtok(Mac,":");
	Mactok[1]=strtok(NULL,":");
        Mactok[2]=strtok(NULL,":");
        Mactok[3]=strtok(NULL,":");
        Mactok[4]=strtok(NULL,":");
        Mactok[5]=strtok(NULL,":");

	sprintf(ep->ether_shost,"%x%x%x%x%x%x",Mactok[0],Mactok[1],Mactok[2],Mactok[3],Mactok[4],Mactok[5]);
	printf("SRC MAP= %x-%x-%x-%x-%x-%x\n",ep->ether_shost[0],ep->ether_shost[1],ep->ether_shost[2],ep->ether_shost[3],ep->ether_shost[4],ep->ether_shost[5]);


}

int main(int argc, char* argv[])
{
 char victmIP[256];
 int i;
 char* tok;
 printf("%s\n", getMyIP());
 printf("%s\n", getMyMac());
 printf("%s\n",getGatewayIP());
 strcpy(victmIP,argv[1]);
 printf("%s\n",victmIP);
 tok=strtok(getMyMac(),":");
 printf("%s\n",tok);
 while(tok = strtok(NULL,":")){
	printf("%s\n",tok);
}
 printf("%s",set_packetToGetMac(getMyIP(),victmIP,getMyMac()));
 return 0;
}
