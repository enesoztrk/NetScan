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


using dev_info_t=std::unordered_map<S_DeviceInfo,hostname_t>;


template<typename T=C_ArpManager, typename U=C_DnsManager>
class CT_NtwrkScan{

public:
    CT_NtwrkScan()=delete;

    CT_NtwrkScan(const pcpp::IPAddress& ethif_ip);

    CT_NtwrkScan(const std::string& ethif_name);
    ~CT_NtwrkScan();

    bool scan_start();
    bool scan_stop();
    dev_info_t& get_device_list()const;
    void set_ip_range(const std::string& first_ip,const std::string& second_ip );

    bool set_ntwrk_filter();

    T& get_arp_instance(){
        return c_arp;
    }

    U& get_dns_instance(){
        return c_dns;
    }
private:
     dev_info_t dev_table{};
    T c_arp;
    U c_dns;
    std::unique_ptr<pcpp::PcapLiveDevice> dev;
    pcpp::IPv4Address low_bound_ip_addr{};
    pcpp::IPv4Address high_bound_ip_addr{};

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
