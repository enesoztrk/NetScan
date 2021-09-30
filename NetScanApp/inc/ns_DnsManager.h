#ifndef NS_DNSMANAGER_H
#define NS_DNSMANAGER_H

#include <iostream>
#include "PcapLiveDeviceList.h"
#include <unordered_map>
#include <string>
#include "Packet.h"
#include "IPv4Layer.h"
#include <memory>

namespace ns {

struct S_DeviceInfo;
class C_DnsManager{

public:
     C_DnsManager(){};
     C_DnsManager(const S_DeviceInfo& host_dev_info):host_ip_mac{host_dev_info}{};
      pcpp::Packet& generate_dns_req(const pcpp::IPv4Address& scanipAddr);
     bool parse_dns_resp();
     std::string& get_hostname()const;
private:

    std::string host_name_str{};
       S_DeviceInfo host_ip_mac;
};


}


#endif // NS_DNSMANAGER_H
