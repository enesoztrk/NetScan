#include<iostream>
#include"ns_ArpManager.h"
#include "ns_SM.h"
#include "ns_NetScan.h"
#include <unistd.h>


/*
https://www.fluentcpp.com/2019/07/02/fseam-a-mocking-framework-that-requires-no-change-in-code-part-1/
*/

bool inactive_test(int i,void* ptr){


std::cout<<"Inactive\n";
return true;
}

bool arpsend_test(int i,void* ptr){


std::cout<<"arp send\n";
return true;
}

bool arp_parse_test(int i,void* ptr){


std::cout<<"arp parse\n";
return true;
}

bool dns_req_test(int i,void* ptr){


std::cout<<"dns_req\n";
return true;
}
bool dns_parse_test(int i,void* ptr){


std::cout<<"Inactive\n";
return true;
}
int main(){


    ns::C_NtwrkScan a{pcpp::IPv4Address("192.168.xx")};

    a.set_ip_range("192.168.xx","192.168.xx");
    a.start();

    //NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(1));

    char c='r';
    int buff_out=12;
   while(1)
   {


        a.run();
        usleep(1000);
   }
    return 0;
}
