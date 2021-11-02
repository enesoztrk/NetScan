#ifndef NS_SM_STATES_H
#define NS_SM_STATES_H

#include<ns_SM.h>
namespace NetScan_SM {
//Declarations
template<int inum>
class DnsMsgSend;



/**
 * @brief Initial state for SM
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
class Inactive
: public MsgStateMachine<inum>
{
private:
    using base = MsgStateMachine<inum>;
   static constexpr unsigned char index=
           static_cast<const unsigned char>(States::INACTIVE);
public:
  void entry() override {
    std::cout << "Inactive State\n";

    base::set_state(States::INACTIVE);

    //stop timer. Packet received
    base::set_timer(false);
    if(nullptr==base::cb_state_process[index])
        throw SM_exception{"Inactive State Callback func is null"};

    //callback function for application
    base::cb_state_process[index](inum,&base::buffer_data);

  };
};


/**
 * @brief SM State to send arp request to network
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
class ArpMsgSend
: public MsgStateMachine<inum>
{
private:
     using base = MsgStateMachine<inum>;
    static constexpr unsigned char index=
            static_cast<const unsigned char>(States::ARP_MSG_SEND);
public:
  void entry() override {
    std::cout << "Arp Send\n" << std::endl;

    base::set_state(States::ARP_MSG_SEND);

    if(nullptr==base::cb_state_process[index])
         throw SM_exception{"ArpMsgSend State Callback func is null"};

    //reset timer
    base::reset();

    //TODO: will be deleted. reset function should
    base::set_timer(true);


    //send packet
   auto ret_val= base::cb_state_process[index](inum,&base::buffer_data);
    if(!ret_val)
    {
        //error generation
        std::cout << "Arp Send Error\n";

    }





  };
};


/**
 * @brief SM State to parse arp response for incoming packets
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */

template<int inum>
class ArpMsgParse
: public MsgStateMachine<inum>
{
private:
    using base = MsgStateMachine<inum>;
   static constexpr unsigned char index=
           static_cast<const unsigned char>(States::ARP_MSG_PARSE);
public:
  void entry() override {
       std::cout << "Arp Parse\n";


      if(nullptr==base::cb_state_process[index])
         throw SM_exception{"ArpMsgParse State Callback func is null"};

      base::set_state(States::ARP_MSG_PARSE);

      auto ret_val=base::cb_state_process[index](inum,&base::buffer_data);

      //stop timer. Packet received
      base::set_timer(false);

      if(ret_val)
      {
           base::template transit<DnsMsgSend<inum>>();
      }
      else {
           //error occured, go to inactive state
          // base::template transit < Inactive<inum>>();
      }

  };
};


/**
 * @brief SM State to send dns request
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
class DnsMsgSend
: public MsgStateMachine<inum>
{
private:
     using base = MsgStateMachine<inum>;
    static constexpr unsigned char index=
            static_cast<const unsigned char>(States::DNS_MSG_SEND);
public:
  void entry() override {
    std::cout << "Dns Send\n";
    if(nullptr==base::cb_state_process[index])
        throw SM_exception{"DnsMsgSend State Callback func is null"};



    //reset timer
    base::reset();

    base::set_state(States::DNS_MSG_SEND);


    //send packet
    auto ret_val = base::cb_state_process[index](inum, &base::buffer_data);
    if (!ret_val)
    {
        //error generation
        std::cout << "Dns Send Error\n";

    }

  };
};


/**
 * @brief SM State to parse dns response for incoming packets
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
class DnsMsgParse
: public MsgStateMachine<inum>
{
private:
    using base = MsgStateMachine<inum>;
   static constexpr unsigned char index=
           static_cast<const unsigned char>(States::DNS_MSG_PARSE);
public:
  void entry() override {
    std::cout << "Dns Parse\n";

    if(nullptr==base::cb_state_process[index])
         throw SM_exception{"DnsMsgParse State Callback func is null"};

    //stop timer. Packet received
    base::set_timer(false);

    base::cb_state_process[index](inum,&base::buffer_data);
    base::set_state(States::DNS_MSG_PARSE);
    base::template transit < Inactive<inum>>();
  };
};

/**
 * @brief Communication timeout
 *
 *
 * @param none
 * @return
 * @note
 * @warning Warning.
 */
template<int inum>
class CommTimeout
: public MsgStateMachine<inum>
{
private:

    using base = MsgStateMachine<inum>;
    static constexpr unsigned char index=
            static_cast<const unsigned char>(States::COMM_TIMEOUT);
public:
  void entry() override {
    std::cout << "Communication Timeout: "<< MsgStateMachine<inum>::get_tick()<<"\n";
   auto ret_val= MsgStateMachine<inum>::get_tick();
    base::set_state(States::COMM_TIMEOUT);
   if(nullptr==base::cb_state_process[index])
       throw SM_exception{"CommTimeout State Callback func is null"};

   base::cb_state_process[index](inum,&base::buffer_data);



  };
};
}
#endif // NS_SM_STATES_H
