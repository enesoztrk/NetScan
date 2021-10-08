#ifndef __MOCK_ARPMANAGER_H__
#define __MOCK_ARPMANAGER_H__
#include <gmock/gmock.h>
#include "../NetScanApp/inc/ns_ArpManager.h"
#include <cstdlib>

namespace ns {

inline void* mock_Arp_ptr{nullptr};

class MockC_ArpManager : public C_ArpManager {
private:

 public:
 MOCK_METHOD(void, C_ArpManager, (const S_DeviceInfo& netif_info,S_DeviceInfo& gateway_ip_mac_param));
  MOCK_METHOD(pcpp::Packet&, generate_arp_req, (const pcpp::IPv4Address& scanipAddr));
  MOCK_METHOD(bool, parse_arp_resp, ());

  MockC_ArpManager(const S_DeviceInfo& netif_info,S_DeviceInfo& gateway_ip_mac_param):ns::C_ArpManager(netif_info,gateway_ip_mac_param){

  }



  //same address will returned for all of new operator calls
  void * operator new(size_t size){

      std::cout<<__PRETTY_FUNCTION__<<"\n";
      void * p {nullptr};
      if(!ns::mock_Arp_ptr){

            p =::operator new(size);
            ns::mock_Arp_ptr=p;
      }
        else{

          p=ns::mock_Arp_ptr;
      }




     return p;




  }



 virtual ~MockC_ArpManager() = default;


};





}  // namespace ns




#endif


