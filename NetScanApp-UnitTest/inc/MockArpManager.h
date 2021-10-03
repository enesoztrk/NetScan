#ifndef __MOCK_ARPMANAGER_H__
#define __MOCK_ARPMANAGER_H__
#include <gmock/gmock.h>
#include "../NetScanApp/inc/ns_ArpManager.h"


namespace ns {

class MockC_ArpManager : public C_ArpManager {
 public:
  MOCK_METHOD(void, C_ArpManager, ());
  MOCK_METHOD(void, C_ArpManager, (const S_DeviceInfo& host_dev_info));
  MOCK_METHOD(pcpp::Packet&, generate_arp_req, (const pcpp::IPv4Address& scanipAddr));
  MOCK_METHOD(bool, parse_arp_resp, ());
};

}  // namespace ns




#endif


