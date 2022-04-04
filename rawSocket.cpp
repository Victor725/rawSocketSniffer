#include<sys/socket.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>

//ioctl and ifreq
#include<sys/ioctl.h>
#include<net/if.h>

#include "rawSocket.h"

rawsocket::rawsocket(const int protocol)
{
    sockfd=socket(PF_PACKET,SOCK_RAW,protocol);
    if(sockfd<0)
    {
	    perror("socket error: ");
    }
}

rawsocket::~rawsocket()
{
    close(sockfd);
}


bool rawsocket::dopromisc(char*nif)
{
    struct ifreq ifr;              
    strncpy(ifr.ifr_name, nif,strlen(nif)+1);  
    if((ioctl(sockfd, SIOCGIFFLAGS, &ifr) == -1))  
    {         
       	perror("ioctlread: ");  
	    return false;
    }	
    ifr.ifr_flags |= IFF_PROMISC; 
    if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) == -1 )
    { 
     	perror("ioctlset: ");
	    return false;
    }
    return true;
}

int rawsocket::receive(char *recvbuf,int buflen, struct sockaddr_in *from,int *addrlen)
{
    int recvlen;
    recvlen=recvfrom(sockfd,recvbuf,buflen,0,(struct sockaddr *)from,(socklen_t *)addrlen);
    recvbuf[recvlen]='\0';
    return recvlen;
}


