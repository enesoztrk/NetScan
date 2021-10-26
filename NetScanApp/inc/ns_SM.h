#ifndef NS_SM_H
#define NS_SM_H
#include "ns_SM_common.h"
#include<functional>


namespace NetScan_SM {
// ----------------------------------------------------------------------------
// 1. Event Declarations
//
struct Arp_MsgSend : tinyfsm::Event {

    Arp_MsgSend(int i) :param{ i } {}
    int param;
};
struct Arp_MsgRecv : tinyfsm::Event {

    Arp_MsgRecv(int i) :param{ i } {}
    int param;
};
struct Dns_MsgRecv : tinyfsm::Event { };
struct Timer_check : tinyfsm::Event {

    Timer_check(unsigned int tick_param) :tick{ tick_param } {}

    unsigned int tick{};

};


// ----------------------------------------------------------------------------
// 2. State Machine Base Class Declaration
//


template<int inum>
class MsgStateMachine
: public tinyfsm::Fsm< MsgStateMachine<inum> >
{


public:



static void reset();


/* default reaction for unhandled events */
void react(tinyfsm::Event const &);

/*Function to invoke SM  arp response receiving states*/
bool invoke_ArpMsgRecv_state(void* data_param);

/*Function to invoke SM  for sending arp request to network*/
friend  bool invoke_ArpMsgsend_state(void* data_param);

/*Receiving Arp Response event */
void react(Arp_MsgRecv const &);

/*Receiving Dns Response event */
void react(Dns_MsgRecv const &);

/*Checking timeout event */
void react(Timer_check const &);
void react(Arp_MsgSend const &);

virtual void entry(void) { };  /* entry actions in some states */
void         exit(void)  { };  /* no exit actions */


/*Register callbacks to call inside the states*/
static void register_callback(const cb_t &cb,States cb_state);

//will be private - get/set functions will be added
static inline void* buffer_data{ nullptr };

private:
static inline unsigned int tick_passed{};
static inline std::pair<States, std::string> prev_state{ States::INACTIVE,States_table[States::INACTIVE] };
static inline std::pair<States, std::string> curr_state{ States::INACTIVE,States_table[States::INACTIVE] };
static constexpr unsigned char NUM_CB_FUNC=
      static_cast<const unsigned char>(States::COMM_TIMEOUT)+1;
static inline bool timer_enable_flag{false};


protected:
static constexpr inline auto timeout_val=500;

static inline std::function<bool(const int,void*)> cb_state_process[NUM_CB_FUNC]{nullptr};

void increase_tick(unsigned int tick_param);

bool set_state(const States& new_state);


static void set_timer(bool status);

bool is_timer_on()const;


public:

static std::pair<States, std::string>& get_state(void);

};


}//namespace


#endif // NS_SM_H
