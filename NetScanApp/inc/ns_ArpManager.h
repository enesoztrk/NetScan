#ifndef __NS_ARPMANAGER_H__
#define __NS_ARPMANAGER_H__

#include <iostream>
#include "PcapLiveDeviceList.h"
#include <unordered_map>
#include <string>
#include "Packet.h"
#include "IPv4Layer.h"
#include <memory>

namespace ns {

using hostname_t=std::string;

struct S_DeviceInfo {

    pcpp::IPAddress ip;
    std::string mac_addr;

    // `operator==` is required to compare keys in case of a hash collision
       bool operator==(const S_DeviceInfo &p) const {
           return ip == p.ip && mac_addr == p.mac_addr;
       }

};





class C_ArpManager{

public:
      C_ArpManager()=delete;
      C_ArpManager(const S_DeviceInfo& host_dev_info);
      pcpp::Packet& generate_arp_req(const pcpp::IPv4Address& scanipAddr);
      bool parse_arp_resp();
private:
     std::unique_ptr<S_DeviceInfo> host_ip_mac{};
};
}


#endif



