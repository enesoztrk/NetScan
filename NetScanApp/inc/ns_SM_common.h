#ifndef NS_SM_COMMON_H
#define NS_SM_COMMON_H
#include <tinyfsm.hpp>
#include <iostream>
#include <stdlib.h> /* rand */
#include <map>
#include "ns_SM_utils.h"

namespace ns {

/*forward decleration*/
struct common_data_t;
}
namespace NetScan_SM {
    using namespace tinyfsm;
    using namespace NetScan_SM_Utils;
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


    template<typename... FF>
    struct ST_NetScan_SM_List;

    template<> struct ST_NetScan_SM_List<> : tinyfsm::FsmList<> {

        static void register_callback(const cb_t& cb, States cb_state) {}
        static bool invoke_ArpMsgsend_state(ns::common_data_t& data_param){}
    };

    template<typename F, typename... FF>
    struct ST_NetScan_SM_List<F, FF...> : tinyfsm::FsmList<F, FF...>
    {

        static void register_callback(const cb_t& cb, States cb_state) {
            F::register_callback(cb, cb_state);
            ST_NetScan_SM_List<FF...>::register_callback(cb,cb_state);
        }

        static bool invoke_ArpMsgsend_state(ns::common_data_t& data_param) {

            if(F::invoke_ArpMsgsend_state(data_param))
                return true;
            ST_NetScan_SM_List<FF...>::invoke_ArpMsgsend_state(data_param);
            return false;
        }

    };
}
#endif // NS_SM_COMMON_H
