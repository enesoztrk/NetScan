#ifndef NS_DNSMANAGER_H
#define NS_DNSMANAGER_H

#include <iostream>
#include <string>
#include "ns_Common.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "SystemUtils.h"
#include "UdpLayer.h"
#include <random>
#include "DnsLayer.h"
#include<sstream>

namespace ns {

class C_DnsManager{

public:
     C_DnsManager()=delete;
     /**
       * @brief
       *
       *
       * @param none
       * @return
       * @note
       * @warning Warning.
       */
     C_DnsManager(const S_DeviceInfo& netif_info,S_DeviceInfo& gateway_ip_mac_param):netif_ip_mac{netif_info},gateway_ip_mac{gateway_ip_mac_param}{ }


     /**
       * @brief
       *
       *
       * @param none
       * @return
       * @note   see: https://isocpp.org/wiki/faq/templates#templates-defn-vs-decl
       * @warning Warning.
       */
      template<typename packet_t=pcpp::Packet>
     pcpp::RawPacket& generate_dns_req(const S_DeviceInfo&  scan_dev_info,bool b_mdns=false){

         bool b_ret_val{true};
         //packet
#ifndef MOCK_SUPPORT
         std::unique_ptr<packet_t> packetptr(new packet_t(86));
#else

         packet_t* packetptr;
         packetptr=packetptr->get();
#endif

         /*clear raw packet*/
         raw_packet.clear();

         // create a new Ethernet layer,
             const pcpp::MacAddress source_mac{netif_ip_mac.mac_addr};
             pcpp::MacAddress dest_mac{};

             if(!b_mdns)
             dest_mac=gateway_ip_mac.mac_addr;
             else {
                dest_mac= mdns_mac_addr;
             }


             pcpp::EthLayer newEthernetLayer( source_mac,dest_mac,PCPP_ETHERTYPE_IP);



         //create IPV4 layer

             pcpp::IPv4Layer newIPLayer(netif_ip_mac.ip.getIPv4(), gateway_ip_mac.ip.getIPv4());

             if(b_mdns)
              newIPLayer.setDstIPv4Address(mdns_ip_addr);



             newIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(2000);
             newIPLayer.getIPv4Header()->ipVersion=4;
             newIPLayer.getIPv4Header()->internetHeaderLength=5;
             newIPLayer.getIPv4Header()->timeToLive = 250;
             newIPLayer.getIPv4Header()->protocol=pcpp::IPProtocolTypes::PACKETPP_IPPROTO_UDP;

        //create Udp Layer

             std::random_device dev;
             std::mt19937 rng(dev());
             std::uniform_int_distribution<std::mt19937::result_type> dist40000(1024,40000); // distribution in range [1024,40000 ]
              int udp_dns_port_param=C_DnsManager::udp_dns_port_num;


             if(b_mdns)
                udp_dns_port_param=C_DnsManager::udp_mdns_port_num;

             pcpp::UdpLayer newUdpLayer(dist40000(rng),udp_dns_port_param);




         //Dns query
            pcpp::DnsLayer newDnsLayer;

            newDnsLayer.getDnsHeader()->numberOfAnswers=0;

            if(!b_mdns)
                newDnsLayer.getDnsHeader()->recursionDesired=1;
            else
                newDnsLayer.getDnsHeader()->recursionDesired=0;

             newDnsLayer.getDnsHeader()->transactionID=dist40000(rng);

            std::string query_name{scan_dev_info.ip.toString()};

            reverse_ipstr(query_name);


            query_name+=".in-addr.arpa";


            newDnsLayer.addQuery(query_name,pcpp::DnsType::DNS_TYPE_PTR,pcpp::DnsClass::DNS_CLASS_IN);
            newDnsLayer.computeCalculateFields();


            if(!packetptr->addLayer(&newEthernetLayer))
            {
                      b_ret_val=false;


            }

            if((false==b_ret_val)||(!packetptr->addLayer(&newIPLayer)))
            {
                      b_ret_val=false;
                packetptr->removeAllLayersAfter(packetptr->getFirstLayer());

            }



            if((false==b_ret_val)||(!packetptr->addLayer(&newUdpLayer)))
            {
                      b_ret_val=false;
                packetptr->removeAllLayersAfter(packetptr->getFirstLayer());

            }

            if((false==b_ret_val)||(!packetptr->addLayer(&newDnsLayer)))
            {
                      b_ret_val=false;
                packetptr->removeAllLayersAfter(packetptr->getFirstLayer());

            }




            packetptr->computeCalculateFields();


            if(b_ret_val)
            raw_packet=*(packetptr->getRawPacket());

            return raw_packet;

     }


      /**
        * @brief
        *
        *
        * @param none
        * @return
        * @note
        * @warning Warning.
        */
    std::pair<std::string, pcpp::IPAddress> parse_dns_resp(const pcpp::Packet& incoming_packet);
     /**
       * @brief
       *
       *
       * @param none
       * @return
       * @note
       * @warning Warning.
       */
     std::string& get_hostname()const;
     /**
       * @brief
       *
       *
       * @param none
       * @return
       * @note
       * @warning Warning.
       */
      const S_DeviceInfo& get_netif_ip_mac()const;



private:
      /**
        * @brief
        *
        *
        * @param none
        * @return
        * @note
        * @warning Warning.
        */
    bool parse_and_reverse_ipstr(std::string&)const;
    /**
      * @brief
      *
      *
      * @param none
      * @return
      * @note
      * @warning Warning.
      */
    bool reverse_ipstr(std::string&)const;

    std::string dev_host_name_str{};
    const S_DeviceInfo netif_ip_mac;
    constexpr static int udp_dns_port_num=53;
    constexpr static unsigned int udp_mdns_port_num=5353;
    const  pcpp::IPv4Address mdns_ip_addr{"224.0.0.251"};
     const  pcpp::MacAddress mdns_mac_addr{"01:00:5e:00:00:fb"};
    S_DeviceInfo& gateway_ip_mac;
    pcpp::RawPacket raw_packet;
};


}


#endif // NS_DNSMANAGER_H
