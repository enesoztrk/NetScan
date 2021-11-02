#include "ns_SM.h"
#include "ns_SM_States.h"
namespace  NetScan_SM{

//State lookup table
std::map<States, std::string> States_table{

{States::ARP_MSG_SEND,"ARP-MSG-SENT"},
{States::DNS_MSG_SEND,"DNS-MSG-SENT"},
{States::ARP_MSG_PARSE,"ARP-MSG-PARSE"},
{States::DNS_MSG_PARSE,"DNS-MSG-PARSE"},
{States::INACTIVE,"INACTIVE"},
{States::COMM_TIMEOUT,"COMM-TIMEOUT"},


};



//Forward Declaration
template<int inum>
class DnsMsgSend;

/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
 void MsgStateMachine<inum>::reset(){

    static auto is_init = true;

    if (!is_init) {
        set_timer(true);
        tick_passed = 0;


    }
    else {
        is_init = false;

    }


}

 /**
  * @brief
  *
  *
  * @param none
  * @return
  * @note
  * @warning Warning.
  */
template<int inum>
void MsgStateMachine<inum>::increase_tick(unsigned int tick_param){

  tick_passed +=tick_param;
}

/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
unsigned int  MsgStateMachine<inum>::get_tick(void){

  return tick_passed;
}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
bool MsgStateMachine<inum>::set_state(const States& new_state) {

    if(new_state!=curr_state.first)
    curr_state = { new_state,States_table[new_state] };

    return true;
}

/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::set_timer(bool status){

   timer_enable_flag=status;

}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
bool MsgStateMachine<inum>::is_timer_on()const{

    return timer_enable_flag;
}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
std::pair<States, std::string>& MsgStateMachine<inum>::get_state(void) {

    return curr_state;
}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::register_callback(const cb_t &cb,States cb_state){



    cb_state_process[static_cast<const unsigned char>(cb_state)]=cb;

}

// ----------------------------------------------------------------------------
// Base State: default implementations
//

/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::react(Arp_MsgRecv const &) {
     using base = MsgStateMachine<inum>;
    base::set_timer(false);
   base::template transit<ArpMsgParse<inum>>();
}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::react(Dns_MsgRecv const &) {
    using base = MsgStateMachine<inum>;

    base::set_timer(false);
  base::template transit<DnsMsgParse<inum>>();

}


/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::react(Arp_MsgSend const &) {
    using base = MsgStateMachine<inum>;


  base::template transit<ArpMsgSend<inum>>();

}

/**
 * @brief
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
void MsgStateMachine<inum>::react(Timer_check const &tick) {
    using base = MsgStateMachine<inum>;

   base::increase_tick(tick.tick);



  if((base::is_timer_on() )&& (base::get_tick()>timeout_val))
     base::template transit<CommTimeout<inum>>();
   else
     return;
}

template<int inum>
bool  MsgStateMachine<inum>::invoke_ArpMsgRecv_state(ns::common_data_t data_param){

    bool ret_val=false;
    if(buffer_data.scan_ip==data_param.scan_ip && get_state().first==States::ARP_MSG_SEND)
    {
        ret_val=true;
        buffer_data.in_packet=data_param.in_packet;
        MsgStateMachine<inum>::dispatch(Arp_MsgRecv(inum));


    }


    //data_param.in_packet={};

   return true;
}


template<int inum>
bool  MsgStateMachine<inum>::invoke_DnsMsgRecv_state(ns::common_data_t* data_param){

    bool ret_val=false;
    if(buffer_data.scan_ip==data_param->scan_ip&& get_state().first==States::DNS_MSG_SEND)
    {
        ret_val=true;
        buffer_data.in_packet=data_param->in_packet;
        MsgStateMachine<inum>::dispatch(Dns_MsgRecv(inum));


    }

    data_param->in_packet={};

   return true;
}


 //template decleration
 template class MsgStateMachine<0>;
 template class MsgStateMachine<1>;
 template class MsgStateMachine<2>;

}//namespace


//Initial state for SMs
FSM_INITIAL_STATE(NetScan_SM::MsgStateMachine<0>, NetScan_SM::Inactive<0> )
FSM_INITIAL_STATE(NetScan_SM::MsgStateMachine<1>, NetScan_SM::Inactive<1> )
FSM_INITIAL_STATE(NetScan_SM::MsgStateMachine<2>, NetScan_SM::Inactive<2> )











