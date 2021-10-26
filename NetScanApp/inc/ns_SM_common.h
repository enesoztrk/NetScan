#ifndef NS_SM_COMMON_H
#define NS_SM_COMMON_H
#include <tinyfsm.hpp>
#include <iostream>
#include <stdlib.h> /* rand */
#include <map>

namespace NetScan_SM {
    using namespace tinyfsm;

//callback function type
    using cb_t = bool(*)(int, void*);

//States
    enum class States {
        ARP_MSG_SEND = 0,
        DNS_MSG_SEND,
        ARP_MSG_PARSE,
        DNS_MSG_PARSE,
        INACTIVE,
        COMM_TIMEOUT
    };

    //State lookup table
    std::map<States, std::string> States_table{

    {States::ARP_MSG_SEND,"ARP-MSG-SENT"},
    {States::DNS_MSG_SEND,"DNS-MSG-SENT"},
    {States::ARP_MSG_PARSE,"ARP-MSG-PARSE"},
    {States::DNS_MSG_PARSE,"DNS-MSG-PARSE"},
    {States::INACTIVE,"INACTIVE"},
    {States::COMM_TIMEOUT,"COMM-TIMEOUT"},


    };

    template<typename... FF>
    struct ST_NetScan_SM_List;

    template<> struct ST_NetScan_SM_List<> : tinyfsm::FsmList<> {

        static void register_callback(const cb_t& cb, States cb_state) {}

    };

    template<typename F, typename... FF>
    struct ST_NetScan_SM_List<F, FF...> : tinyfsm::FsmList<F, FF...>
    {

        static void register_callback(const cb_t& cb, States cb_state) {
            F::register_callback(cb, cb_state);
            ST_NetScan_SM_List<FF...>::register_callback(cb,cb_state);
        }

    };
}
#endif // NS_SM_COMMON_H
