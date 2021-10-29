#ifndef NS_NETSCAN_H
#define NS_NETSCAN_H

#include <iostream>
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include <unordered_map>
#include <string>
#include "Packet.h"
#include "DnsLayer.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "ns_ArpManager.h"
#include "ns_DnsManager.h"
namespace ns {




template<typename T=C_ArpManager, typename U=C_DnsManager>
class CT_NtwrkScan{

public:
    CT_NtwrkScan()=delete;

    CT_NtwrkScan(const pcpp::IPAddress& ethif_ip);

    CT_NtwrkScan(const std::string& ethif_name);


    bool start();
    bool start_packet_capture();
    bool stop_packet_capture();
    bool stop();

    dev_info_t& get_device_list()const;
    void set_ip_range(const std::string& first_ip,const std::string& second_ip );


/*
 * std::pair<std::string, pcpp::IPAddress> ret_val2;
        dev_info_t x;
        S_DeviceInfo temp{pcpp::IPAddress("192.168.1.112"),std::string("aa:bb:cc:aa:aa:aa")};
        S_DeviceInfo TEST{pcpp::IPAddress("192.168.16.1"),std::string("")};
        x[temp]="";

        auto is_ip_same = [&ret_val2](auto& i){ return i.first.ip==ret_val2.second; };

          auto result1 = std::find_if(begin(x), end(x), is_ip_same);

          if(result1!=end(x)){
               result1->second=ret_val2.first;
              std::cout << "found\n";
          }

*/
    bool find_ip_in_device_list();
    bool set_ntwrk_filter();

    T& get_arp_instance(){
        return *c_arp;
    }

    U& get_dns_instance(){
        return *c_dns;
    }
private:
    std::unique_ptr<pcpp::PcapLiveDevice> dev;
    pcpp::IPv4Address low_bound_ip_addr{};
    pcpp::IPv4Address high_bound_ip_addr{};
    dev_info_t dev_table{};

    S_DeviceInfo gateway_mac_ip{ pcpp::IPAddress(""/*dev->getDefaultGateway()*/),std::string("")};
    S_DeviceInfo netif_mac_ip{ pcpp::IPAddress(""/*dev->getIPv4Address()*/),std::string("")/*dev->getMacAddress().toString()*/};
    std::unique_ptr<T> c_arp{new T(netif_mac_ip,gateway_mac_ip)};
    std::unique_ptr<U> c_dns{new U(netif_mac_ip,gateway_mac_ip)};

    bool add_dev_list(const pcpp::MacAddress&);//add mac address
    bool add_dev_list(const std::string&);//add dns hostname
    /**
     * A callback function for the async capture which is called each time a packet is captured
     */
    static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);



};

using C_NtwrkScan=CT_NtwrkScan<>;

}

#endif // NS_NETSCAN_H
