#include<iostream>
#include"ns_ArpManager.h"
#include "ns_SM.h"
#include "ns_NetScan.h"


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


    ns::C_NtwrkScan a{pcpp::IPv4Address("192.168.50.104")};

    a.set_ip_range("192.168.50.102","192.168.50.253");
    a.start();

    //NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(1));

    char c='r';
    int buff_out=12;
   while(1)
   {


        a.run();

//     std::cout << std::endl << "0,1,2=Toggle single, a=Toggle all, r=Restart, q=Quit ? ";
//    // std::cin >> c;

//     switch(c) {
//     case 'r':
//     {
//           NetScan_SM::invoke_ArpMsgsend_state<0>(&buff_out);
//        // NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(NetScan_SM::get_ticks_passed_until_now()));
//            c='t';
//     }
//         break;

//     case 't':
//     {
//            NetScan_SM::MsgStateMachine<0>::invoke_ArpMsgRecv_state(&buff_out);
//        // NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(NetScan_SM::get_ticks_passed_until_now()));

//     }
//         break;

//     case 'q':
//       return 0;
//     default:
//       std::cout << "> Invalid input" << std::endl;
//     };
   }
    return 0;
}
