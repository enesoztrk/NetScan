#ifndef NS_DNSMANAGER_H
#define NS_DNSMANAGER_H

#include <iostream>
#include <string>
#include "ns_Common.h"

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
     C_DnsManager(const S_DeviceInfo&  netif_info):netif_ip_mac{netif_info}{};

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
      pcpp::RawPacket& generate_dns_req(const pcpp::IPv4Address& scanipAddr);


      /**
        * @brief
        *
        *
        * @param none
        * @return
        * @note
        * @warning Warning.
        */
     std::string& parse_dns_resp(const pcpp::Packet& incoming_packet);
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

    std::string dev_host_name_str{};
    const S_DeviceInfo netif_ip_mac;

};


}


#endif // NS_DNSMANAGER_H
