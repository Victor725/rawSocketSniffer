#include "rawSocSniffer.h"
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<iostream>
#include<iomanip>
#include<stdio.h>
#include<cstring>
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
};


typedef struct arp_packet_t{
    ether_header_t etherheader;
    arp_header_t arpheader;
} arp_packet_t;

typedef struct ip_packet_t{
    ether_header_t ether_header;
    ip_header_t ipheader;
};

typedef struct icmp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    icmp_header_t icmpheader;
};

typedef struct tcp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    tcp_header_t tcpheader;
};

typedef struct udp_packet_t{
    ether_header_t etherheader;
    ip_header_t ipheader;
    udp_header_t udpheader;
};

#pragma pack()


rawsocsniffer::rawsocsniffer(int protocol, char* device_name):rawsocket(protocol){
    packet=new char[max_packet_len];
    memset(packet,0,max_packet_len);
    init(device_name);
}

bool rawsocsniffer::init(char* device_name){
    return dopromisc(device_name);
}


void rawsocsniffer::setfilter(filter myfilter)
{
    simfilter.protocol=myfilter.protocol;
    simfilter.sip=myfilter.sip;
    simfilter.dip=myfilter.dip;
}

bool rawsocsniffer::testbit(const unsigned int p,int k)
{
    if((p>>(k-1))&0x0001)
	    return true;
    else
	    return false;
}

void rawsocsniffer::setbit(unsigned int &p,int k)
{
    p=(p)|((0x0001)<<(k-1));
}

void rawsocsniffer::sniffer()
{
    struct sockaddr_in from;
    int sockaddr_len=sizeof(struct sockaddr_in);
    int recvlen=0;
    while(1)
    {
    	recvlen=receive(packet,max_packet_len,&from,&sockaddr_len);
    	if(recvlen>0)
    	{
	        analyze();
    	}
   	    else
    	{
	        continue;
    	}
    }	 
}

void rawsocsniffer::analyze()
{
    ether_header_t *etherpacket=(ether_header_t *)packet;
    if(simfilter.protocol==0)
	    simfilter.protocol=0xff;

    switch (ntohs(etherpacket->frametype))
    {
	case 0x0800:
	    if(((simfilter.protocol)>>1))
	    {
	    	cout<<"\n\n/*---------------ip packet--------------------*/"<<endl;
	    	ParseIPPacket();
	    }
	    break;
	case 0x0806:
	    if(testbit(simfilter.protocol,1))
	    {
	    	cout<<"\n\n/*--------------arp packet--------------------*/"<<endl;
	    	ParseARPPacket();
	    }
	    break;
	case 0x0835:
	    if(testbit(simfilter.protocol,5))
	    {
		    cout<<"\n\n/*--------------RARP packet--------------------*/"<<endl;
		    ParseRARPPacket();
	    }
	    break;
	default:
	    cout<<"\n\n/*--------------Unknown packet----------------*/"<<endl;
	    cout<<"Unknown ethernet frametype!"<<endl;
	    break;
    }
}


void rawsocsniffer::print_hw_addr(const unsigned char *ptr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
}

void rawsocsniffer::print_ip_addr(const unsigned long ip){
    in_addr ip_i;
    ip_i.s_addr=ip;
    printf("%s\n",inet_ntoa(ip_i));
}


void rawsocsniffer::ParseARPPacket()
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

void rawsocsniffer::ParseRARPPacket()
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


void rawsocsniffer::ParseIPPacket()
{
    ip_packet_t *ippacket=(ip_packet_t *)packet; 
    cout<<"ipheader.protocol: "<<int(ippacket->ipheader.protocol)<<endl;
    if(simfilter.sip!=0)
    {
	    if(simfilter.sip!=(ippacket->ipheader.src_ip)){
            return;
        }
    }
    if(simfilter.dip!=0)
    {
	    if(simfilter.dip!=(ippacket->ipheader.des_ip)){
	        return;
        }
    }
    switch (int(ippacket->ipheader.protocol))
    {
	case 1:
	    if(testbit(simfilter.protocol,4))
	    {
	    	cout<<"Received an ICMP packet"<<endl;
	    	ParseICMPPacket();
	    }
	    break;
	case 6:
	    if(testbit(simfilter.protocol,2))
	    {
	    	cout<<"Received an TCP packet"<<endl;
	    	ParseTCPPacket();
	    }
	    break;
	case 17:
	    if(testbit(simfilter.protocol,3))
	    {
	    	cout<<"Received an UDP packet"<<endl;
	    	ParseUDPPacket();
	    }
	    break;
    }
}


void rawsocsniffer::ParseICMPPacket()
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


void rawsocsniffer::ParseTCPPacket()
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


void rawsocsniffer::ParseUDPPacket()
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

