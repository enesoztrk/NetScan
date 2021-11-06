#ifndef NS_SM_H
#define NS_SM_H
#include "ns_SM_common.h"
#include<functional>
#include<exception>
#include "ns_Common.h"
namespace NetScan_SM {

extern  std::map<States, std::string> States_table;

class SM_exception : public std::logic_error {
public:

 SM_exception(const std::string& ex ): std::logic_error(ex){}

};


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
struct Dns_MsgRecv : tinyfsm::Event {
    Dns_MsgRecv(int i) :param{ i } {}
    int param;

};
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
static bool invoke_ArpMsgRecv_state(const ns::common_data_t& data_param);

/*Function to invoke SM  dns response receiving states*/
static bool invoke_DnsMsgRecv_state(const ns::common_data_t& data_param);

/*Function to invoke SM  for sending arp request to network*/
static  void invoke_ArpMsgsend_state(bool& ret_val,const ns::common_data_t& data_param);

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


//TODO: will be private - get/set functions will be added
static  ns::common_data_t buffer_data;

private:
static unsigned int tick_passed;
static inline std::pair<States, std::string> prev_state{ States::INACTIVE,States_table[States::INACTIVE] };
static  std::pair<States, std::string>  curr_state;
static constexpr unsigned char NUM_CB_FUNC=
      static_cast<const unsigned char>(States::COMM_TIMEOUT)+1;
static bool timer_enable_flag;

static  bool is_init;
protected:
static constexpr inline auto timeout_val=750;

static inline std::function<bool(const int,void*)> cb_state_process[NUM_CB_FUNC]{nullptr};

void increase_tick(unsigned int tick_param);
unsigned int  get_tick(void);


bool set_state(const States& new_state);


static void set_timer(bool status);

bool is_timer_on()const;


public:

static std::pair<States, std::string>& get_state(void);

};

template<int inum>
std::pair<States, std::string>  MsgStateMachine<inum>::curr_state{States::INACTIVE,States_table[States::INACTIVE]  };

template<int inum>
unsigned int  MsgStateMachine<inum>::tick_passed{};

template<int inum>
ns::common_data_t MsgStateMachine<inum>::buffer_data{};

template<int inum>
bool MsgStateMachine<inum>::timer_enable_flag{false};

template<int inum>
bool MsgStateMachine<inum>::is_init{ true };

// ----------------------------------------------------------------------------
// 4. State Machine List Declaration
//
using fsm_handle = NetScan_SM::ST_NetScan_SM_List<
  NetScan_SM::MsgStateMachine<0>,
  NetScan_SM::MsgStateMachine<1>,
  NetScan_SM::MsgStateMachine<2>,
  NetScan_SM::MsgStateMachine<3>,
  NetScan_SM::MsgStateMachine<4>
  >;

}//namespace







#endif // NS_SM_H
