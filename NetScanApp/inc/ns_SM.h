#ifndef NS_SM_H
#define NS_SM_H
#include "ns_SM_common.h"
#include<functional>
#include<exception>
#include "ns_Common.h"
namespace NetScan_SM {

extern std::map<States, std::string> States_table;

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
static bool invoke_ArpMsgRecv_state(ns::common_data_t data_param);

/*Function to invoke SM  dns response receiving states*/
static bool invoke_DnsMsgRecv_state(ns::common_data_t& data_param);

/*Function to invoke SM  for sending arp request to network*/
friend  bool invoke_ArpMsgsend_state(ns::common_data_t& data_param);

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
static inline ns::common_data_t buffer_data{};

private:
static inline unsigned int tick_passed{};
static inline std::pair<States, std::string> prev_state{ States::INACTIVE,States_table[States::INACTIVE] };
static inline std::pair<States, std::string> curr_state{States::INACTIVE,States_table[States::INACTIVE]  };
static constexpr unsigned char NUM_CB_FUNC=
      static_cast<const unsigned char>(States::COMM_TIMEOUT)+1;
static inline bool timer_enable_flag{false};

static inline auto is_init = true;
protected:
static constexpr inline auto timeout_val=1000;

static inline std::function<bool(const int,void*)> cb_state_process[NUM_CB_FUNC]{nullptr};

void increase_tick(unsigned int tick_param);
unsigned int  get_tick(void);


bool set_state(const States& new_state);


static void set_timer(bool status);

bool is_timer_on()const;


public:

static std::pair<States, std::string>& get_state(void);

};

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
bool invoke_ArpMsgsend_state(ns::common_data_t& data_param) {

  auto& state=MsgStateMachine<inum>::get_state().first;
  bool ret_val=false;
    if (States::INACTIVE==state ||
        States::COMM_TIMEOUT==state ) {

        //pass data to be sent to network
        MsgStateMachine<inum>::buffer_data = data_param;
        MsgStateMachine<inum>::dispatch(Arp_MsgSend(inum));
        ret_val=true;
    }


    return ret_val;
}
// ----------------------------------------------------------------------------
// 4. State Machine List Declaration
//
using fsm_handle = NetScan_SM::ST_NetScan_SM_List<
  NetScan_SM::MsgStateMachine<0>,
  NetScan_SM::MsgStateMachine<1>,
  NetScan_SM::MsgStateMachine<2>
  >;

}//namespace







#endif // NS_SM_H
