#include "rawSocSniffer.h"
#include<netinet/in.h>
#include<linux/if_ether.h>
#include<iostream>
#include<string.h>
#include<arpa/inet.h>
using namespace std;

unsigned int bin_to_uint(char* s){
    unsigned int result=0;
    for(int i=strlen(s)-1;i>=0;i--){
        result=result*2+s[i]-'0';
    }
    return result;
}

int main(){
    char device_name[20];
    cout<<"please input device name : "<<endl;
    cin>>device_name;
    rawsocsniffer rs(htons(ETH_P_ALL),device_name);
    filter myfilter;
    char proto_s[5];
    cout<<"please input protocol to listen (10000b----RARP  1000b----ICMP  100b----UDP  10b----TCP  1b----ARP) : "<<endl;
    cin>>proto_s;

    myfilter.protocol=bin_to_uint(proto_s);

    char ip_s[16];
    cout<<"please input source ip of filter : "<<endl;
    cin>>ip_s;
    myfilter.sip=inet_addr(ip_s);

    cout<<"please input destination ip of filter : "<<endl;
    cin>>ip_s;
    myfilter.dip=inet_addr(ip_s);

    rs.setfilter(myfilter);

    rs.sniffer();
}