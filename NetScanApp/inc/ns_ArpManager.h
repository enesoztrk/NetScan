#ifndef __NS_ARPMANAGER_H__
#define __NS_ARPMANAGER_H__

#include <iostream>
#include <memory>
#include "EthLayer.h"
#include "ns_Common.h"
namespace ns {






class C_ArpManager{
private:
     const S_DeviceInfo netif_ip_mac;
     pcpp::RawPacket raw_packet;

public:
    C_ArpManager()=delete;
    C_ArpManager(const C_ArpManager&)=delete;
    C_ArpManager& operator=(const C_ArpManager&)=delete;
    C_ArpManager(C_ArpManager&&)=delete ;
    C_ArpManager& operator=(C_ArpManager&&)=delete ;
    /**
      * @brief Ctor to initilase host ethernet interface ip and mac values
      *
      *
      * @param S_DeviceInfo -> it must contain host device ip and mac information correctly
      * @return none
      * @note
      * @warning Warning.
      */
    C_ArpManager(const S_DeviceInfo& netif_info):netif_ip_mac{netif_info}{ }

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
     pcpp::RawPacket& generate_arp_req(const pcpp::IPv4Address& scanipAddr){

         bool b_ret_val{true};
        #ifndef MOCK_SUPPORT
         std::unique_ptr<packet_t> packetptr(new packet_t(42));
        #else

         packet_t* packetptr;
         packetptr=packetptr->get();
        #endif
           /*clear raw packet*/
           raw_packet.clear();

           // create a new Ethernet layer
         const pcpp::MacAddress source_mac{get_netif_ip_mac().mac_addr};
         const pcpp::MacAddress dest_mac_eth_broadcast{"ff:ff:ff:ff:ff:ff"};

         pcpp::EthLayer newEthernetLayer( source_mac,dest_mac_eth_broadcast,PCPP_ETHERTYPE_ARP);

         // create a new Arp layer,

         const pcpp::MacAddress dest_mac_arp{"00:00:00:00:00:00"};
         pcpp::ArpLayer newArpLayer( pcpp::ARP_REQUEST,
                                     source_mac,
                                     dest_mac_arp,
                                     get_netif_ip_mac().ip.getIPv4(),
                                     scanipAddr);



         //packet creation to be sent network
         if(!packetptr->addLayer(&newEthernetLayer))
         {
                   b_ret_val=false;


         }

         if((false==b_ret_val)||(!packetptr->addLayer(&newArpLayer)))
         {
                   b_ret_val=false;

                packetptr->removeFirstLayer();
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
      S_DeviceInfo parse_arp_resp(const pcpp::Packet& incoming_packet);




};//C_ArpManager




}//ns namespace






#endif



