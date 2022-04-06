#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <iomanip>
//#include <arpa/inet.h>
using namespace std;

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;


#pragma pack(1)
typedef struct ether_header_t{
    BYTE des_hw_addr[6];    //目的MAC地址
    BYTE src_hw_addr[6];    //源MAC地址
    WORD frametype;       //数据长度或类型
} ether_header_t;


typedef struct ip_header_t{
    BYTE hlen_ver;         //头部长度和版本信息
    BYTE tos;              //8位服务类型
    WORD total_len;        //16位总长度
    WORD id;             //16位标识符
    WORD flag;           //3位标志+13位片偏移
    BYTE ttl;             //8位生存时间
    BYTE protocol;        //8位上层协议号    
    WORD checksum;      //16位校验和
    DWORD src_ip;       //32位源IP地址                  
    DWORD des_ip;      //32位目的IP地址
} ip_header_t;

typedef struct arp_header_t{
    WORD hw_type;          //16位硬件类型
    WORD prot_type;         //16位协议类型
    BYTE hw_addr_len;       //8位硬件地址长度
    BYTE prot_addr_len;      //8位协议地址长度
    WORD flag;             //16位操作码
    BYTE send_hw_addr[6];   //源Ethernet网地址
    DWORD send_prot_addr;  //源IP地址
    BYTE des_hw_addr[6];    //目的Ethernet网地址
    DWORD des_prot_addr;   //目的IP地址
} arp_header_t;

typedef struct tcp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口
    DWORD seq;             //seq号
    DWORD ack;             //ack号
    BYTE len_res;            //头长度
    BYTE flag;               //标志字段 
    WORD window;           //窗口大小
    WORD checksum;         //校验和
    WORD urp;              //紧急指针 
} tcp_header_t;

typedef struct udp_header_t{
    WORD src_port;          //源端口
    WORD des_port;          //目的端口 
    WORD len;              //数据报总长度
    WORD checksum;        //校验和
} udp_header_t;

typedef struct icmp_header_t{
    BYTE type;  //类型  
	BYTE code;  //代码  
	WORD checksum;  //校验和  
	WORD id;  //标识  
	WORD seq; //序列号
} icmp_header_t;


typedef struct arp_packet_t{
    ether_header_t etherheader;
    arp_header_t arpheader;
} arp_packet_t;

typedef struct ip_packet_t{
    ether_header_t ether_header;
    ip_header_t ipheader;
}ip_packet_t;

typedef struct icmp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    icmp_header_t icmpheader;
}icmp_packet_t;

typedef struct tcp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    tcp_header_t tcpheader;
}tcp_packet_t;

typedef struct udp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    udp_header_t udpheader;
}udp_packet_t;

#pragma pack()

void print_hw_addr(const unsigned char *ptr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
}

void print_ip_addr(const unsigned long ip){
    in_addr ip_i;
    ip_i.s_addr=ip;
    printf("%s\n",inet_ntoa(ip_i));
}

void ParseICMPPacket(const unsigned char* packet)
{
    icmp_packet_t *icmppacket=(icmp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(icmppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(icmppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(icmppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(icmppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(12)<<"icmp type: "<<int(icmppacket->icmpheader.type)<<" icmp code: "<<int(icmppacket->icmpheader.code)<<endl;
    cout<<setw(12)<<"icmp id: "<<ntohs(icmppacket->icmpheader.id)<<" icmp seq: "<<ntohs(icmppacket->icmpheader.seq)<<endl;
}


void ParseTCPPacket(const unsigned char* packet)
{
    tcp_packet_t *tcppacket=(tcp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(tcppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(tcppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(tcppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(tcppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(10)<<"srcport: "<<ntohs(tcppacket->tcpheader.src_port)<<" desport: "<<ntohs(tcppacket->tcpheader.des_port)<<endl;
    cout<<"seq: "<<ntohl(tcppacket->tcpheader.seq)<<" ack: "<<ntohl(tcppacket->tcpheader.ack)<<endl;
}


void ParseUDPPacket(const unsigned char* packet)
{
    udp_packet_t *udppacket=(udp_packet_t *)packet;
    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(udppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(udppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(udppacket->ipheader.src_ip);
    cout<<"to ";
    print_ip_addr(udppacket->ipheader.des_ip);
    cout<<endl;
    cout<<setw(10)<<"srcport: "<<ntohs(udppacket->udpheader.src_port)<<" desport: "<<ntohs(udppacket->udpheader.des_port)\
	<<" length:"<<ntohs(udppacket->udpheader.len)<<endl;
}


void ParseIPPacket(const unsigned char* packet)
{
    ip_packet_t *ippacket=(ip_packet_t *)packet; 
    printf("ipheader.protocol: %d\n",ippacket->ipheader.protocol);
    switch (ippacket->ipheader.protocol)
    {
	  case 1:
	    printf("Received an ICMP packet\n");
	    ParseICMPPacket(packet);
	    break;
	  case 6:
	    printf("Received an TCP packet\n");
	    ParseTCPPacket(packet);
	    break;
	  case 17:
	    printf("Received an UDP packet\n");
	    ParseUDPPacket(packet);
	    break;
    }
}


void ParseARPPacket(const unsigned char* packet)
{
    arp_packet_t *arppacket=(arp_packet_t *)packet;

    switch(ntohs(arppacket->arpheader.flag)){
    case 0x0001:
        cout<<"ARP request"<<endl;
        break;
    case 0x0002:
        cout<<"ARP reply"<<endl;
        break;
    }

    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(arppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(arppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(arppacket->arpheader.send_prot_addr);
    cout<<"to ";
    print_ip_addr(arppacket->arpheader.des_prot_addr);
    cout<<endl;
}

void ParseRARPPacket(const unsigned char* packet)
{
    arp_packet_t *arppacket=(arp_packet_t *)packet;

    switch(ntohs(arppacket->arpheader.flag)){
    case 0x0003:
        cout<<"RARP request"<<endl;
        break;
    case 0x0004:
        cout<<"RARP reply"<<endl;
    }

    cout<<setw(20)<<"MAC address: from ";
    print_hw_addr(arppacket->etherheader.src_hw_addr);
    cout<<"to ";
    print_hw_addr(arppacket->etherheader.des_hw_addr);
    cout<<endl<<setw(20)<<"IP address: from ";
    print_ip_addr(arppacket->arpheader.send_prot_addr);
    cout<<"to ";
    print_ip_addr(arppacket->arpheader.des_prot_addr);
    cout<<endl;
}



void Packethandler(unsigned char *argument,const struct pcap_pkthdr* packet_header,const unsigned char* packet){
  ether_header_t *etherpacket=(ether_header_t *)packet;
  switch (ntohs(etherpacket->frametype))
  {
	case 0x0800:
	  printf("\n\n/*---------------ip packet--------------------*/\n");
	  ParseIPPacket(packet);
	  break;
	case 0x0806:
	  printf("\n\n/*--------------arp packet--------------------*/\n");
	  ParseARPPacket(packet);
	  break;
	case 0x0835:
		printf("\n\n/*--------------RARP packet--------------------*/\n");
		ParseRARPPacket(packet);
	  break;
	default:
	  printf("\n\n/*--------------Unknown packet----------------*/\n");
	  printf("Unknown ethernet frametype!\n");
	  break;
  }
}

void ifprint(pcap_if_t* alldevs,int* count1){
  int count=*count1;
  //输出网卡名以及描述信息
	for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
		printf("%d . Name: %s\n", count + 1, d->name);
		if (d->description)
			printf("Description: %s\n", d->description);
		else
			printf("There's no description\n\n");
		//输出IP地址信息
		for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) { //是IPv4地址
				if (a->addr) {
					//->的优先级等同于括号,高于强制类型转换,因为addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型
					printf("Address:%s\n", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
				if (a->netmask) {
					printf("Netmask: %s\n", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				}
				if (a->broadaddr) {
					printf("Broadcast Address: %s\n", inet_ntoa(((struct sockaddr_in*)a->broadaddr)->sin_addr));
				}
				if (a->dstaddr) {
					printf("Destination Address: %s\n", inet_ntoa(((struct sockaddr_in*)a->dstaddr)->sin_addr));
				}
			}
		}
		printf("\n");
		count++;
	}
  *count1=count;
}

int main()
{
  pcap_if_t *devices;
  char errbuf[PCAP_ERRBUF_SIZE+1];
  int count=0;
  if(pcap_findalldevs(&devices,errbuf)==-1)
  {
    printf("Error in pcap_findalldevs() : %s \n",errbuf);
	  return -1;
  }
  else
  {
	  printf("Find the following devices on your machine: \n");
	  ifprint(devices,&count);
  }

  //选择要监听的网卡
	printf("\nWhitch one do you want? Please input the number(1-%d):\n", count);
	int tem = count;
	scanf("%d", &count);

	if (count<1 || count>tem) {
		printf("Input error!");
		return -1;
	}
	count = count - 1; //输入的序号是从1开始的，转换为下标

	//打开网卡
	pcap_if_t* temp = devices;
	for (int i = 0; i < count; i++) {
		temp = temp->next;
	}

  char devname[20];
  memset(devname,0,20);
  memcpy(devname,temp->name,strlen(temp->name));

  unsigned int net_ip;
  unsigned int net_mask;
  if(pcap_lookupnet(devname,&net_ip,&net_mask,errbuf)==-1)
  {
    printf("Error in the pcap_lookupnet: %s \n",errbuf);
    return 0;
  }

  pcap_t* dev_handle_pcap;
  if((dev_handle_pcap=pcap_open_live(devname,BUFSIZ,1,100,errbuf))==NULL)
  {
    printf("Error in the pcap_open_live! \n");
    return 0;
  }

  char bpf_filter_string[100]="";
  printf("please input your filter string: \n");
  scanf("%s",bpf_filter_string);

  struct bpf_program bpf_filter;
  if((pcap_compile(dev_handle_pcap,&bpf_filter,bpf_filter_string,0,net_ip))==-1)
  {
    printf("Error in the pcap_compile! \n");
    return 0;
  }
  else
  {
    if((pcap_setfilter(dev_handle_pcap,&bpf_filter))==-1)
    {
      printf("Error in the pcap_setfilter ! \n");
      return 0;
    }
  }
  cout<<"successfully set filter"<<endl;
  pcap_loop(dev_handle_pcap,-1,Packethandler,NULL);
  pcap_close(dev_handle_pcap);
  return 0;
}

