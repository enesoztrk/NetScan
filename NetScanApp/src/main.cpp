#include<iostream>
#include"ns_ArpManager.h"
#include "ns_SM.h"
#include "ns_NetScan.h"
#include <unistd.h>


/*
https://www.fluentcpp.com/2019/07/02/fseam-a-mocking-framework-that-requires-no-change-in-code-part-1/
*/


int main(){


    ns::C_NtwrkScan a{pcpp::IPv4Address("192.168.50.104")};

    a.set_ip_range("192.168.50.99","192.168.50.200");
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
