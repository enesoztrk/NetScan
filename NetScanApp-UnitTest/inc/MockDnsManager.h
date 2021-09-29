#ifndef __MOCK_DNSMANAGER_H__
#define __MOCK_DNSMANAGER_H__
#include <gmock/gmock.h>
#include "../NetScanApp/inc/ns_DnsManager.h"
namespace ns {

class MockC_DnsManager : public C_DnsManager {
 public:
  MOCK_METHOD(void, C_DnsManager, (const S_DeviceInfo& host_dev_info));
  MOCK_METHOD(pcpp::Packet&, generate_dns_req, (const pcpp::IPv4Address& scanipAddr));
  MOCK_METHOD(bool, parse_dns_resp, ());
  MOCK_METHOD(std::string&, get_hostname, (), (const));
};

}  // namespace ns

#endif
