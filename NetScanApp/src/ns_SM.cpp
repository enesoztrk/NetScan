#include "ns_SM.h"


template<int inum>
void NetScan_SM::MsgStateMachine<inum>::reset(){

    static auto is_init = true;

    if (!is_init) {
        set_timer(true);
        tick_passed = 0;


    }
    else {
        is_init = false;

    }


}

