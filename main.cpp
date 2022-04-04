#include "rawSocSniffer.h"
#include<netinet/in.h>
#include<linux/if_ether.h>

int main(){
    rawsocsniffer rs(htons(ETH_P_ALL));
    rs.sniffer();
}