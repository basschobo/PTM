//packet analysis version 0.1
// dns_ver 0.1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<errno.h>
#include <arpa/inet.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<net/ethernet.h>
#include<sys/socket.h>
#include<pcap/pcap.h>
#include "dcoll.h"

int makers(int protocol_to_sniff)
{
	int rawsock;
	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}
	return rawsock;
}

int bindsockint(char *device, int rawsock, int protocol)
{
	
	struct sockaddr_ll sll;
	struct ifreq ifr;
	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}
	
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol); 
	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}
	return 1;
}

int main(int argc, char* argv[])
{
	int raw;
	unsigned char buf[1514];
	unsigned short ether_type;
	//-i mirroring interface , -d deny_mode
	char opt[2][2] = {"-i", "-d"};
	if(argc <= 1){
		printf("monitoring mode \n");
	}else{
		//printf("option : %d \n",argc);
		for(int i=1;i<argc; i++)
		{//strcmp
			for(int z=0;z<2;z++)
			{
				if(strcmp(argv[i], opt[z] ) == 0)
				{
					printf("-i check %s\n",argv[i+1]);
				}else{
					printf("%s , %s \n",argv[i],opt[z]);
				}
			}
			
			printf("%d , %s\n",i,argv[i]);
		}
	}
	
	raw = makers(ETH_P_ALL);
	bindsockint("enp5s0",raw,ETH_P_ALL);
	
	while(1)
	{
		ssize_t packsize = recv (raw, buf, ETH_FRAME_LEN, 0);
		etherh = (struct ethhdr *)buf;
		ether_type = ntohs(etherh->h_proto);
		
		switch(ether_type)
		{
			case ETHERTYPE_IP :
				//ipv4 				
				break;
			case ETHERTYPE_ARP : 
				//arp
				break;
			case ETHERTYPE_IPV6 : 
				//ipv6
				break;
			default:
				//ETC
				break;
		}
		
	}
	
	return 1;
}
