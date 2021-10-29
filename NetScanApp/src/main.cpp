#include<iostream>
#include"ns_ArpManager.h"
#include "ns_SM.h"



/*
https://www.fluentcpp.com/2019/07/02/fseam-a-mocking-framework-that-requires-no-change-in-code-part-1/
*/

bool inactive_test(int i,void* ptr){


std::cout<<"Inactive\n";
return true;
}
int main(){

    NetScan_SM::MsgStateMachine<0>::register_callback(inactive_test, NetScan_SM::States::INACTIVE);

NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(1));



    return 0;
}
