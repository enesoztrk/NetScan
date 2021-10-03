#include "ns_ArpManager.h"



const ns::S_DeviceInfo& ns::C_ArpManager::get_host_ip_mac()const{

return host_ip_mac;
}







// ns::S_DeviceInfo ns::C_ArpManager::parse_arp_resp(const pcpp::Packet& incoming_packet){


//     std::unique_ptr<pcpp::ArpLayer> arp_packet{incoming_packet.getLayerOfType<pcpp::ArpLayer>()};

//     if(pcpp::ARP_REPLY==(arp_packet->getArpHeader()->opcode)>>8){

//         return S_DeviceInfo(arp_packet->getSenderIpAddr(),arp_packet->getSenderMacAddress().toString());
//     }

//        //RVO-> return value optimization
//       return S_DeviceInfo();
// }


//template function
//Please

