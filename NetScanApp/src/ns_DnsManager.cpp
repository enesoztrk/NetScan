#include "ns_DnsManager.h"






std::pair<std::string, pcpp::IPAddress> ns::C_DnsManager::parse_dns_resp(const pcpp::Packet& incoming_packet){


    auto dns_packet=incoming_packet.getLayerOfType<pcpp::DnsLayer>();

     if(1==dns_packet->getDnsHeader()->queryOrResponse){

         pcpp::DnsResource* dnsquery_ans=  dns_packet->getAnswer(".in-addr.arpa",false);

         if(dnsquery_ans){
             pcpp::DnsResourceDataPtr dataptr=dnsquery_ans->getData();

             std::string ip_addr = dnsquery_ans->getName();

             parse_and_reverse_ipstr(ip_addr);


             //RVO
             return std::make_pair(dataptr.castAs<pcpp::StringDnsResourceData>()->toString(),pcpp::IPAddress{ip_addr});
         }




     }

     //RVO
     return std::make_pair(std::string{""},pcpp::IPAddress{""});

}



bool ns::C_DnsManager::parse_and_reverse_ipstr(std::string& ipstr){

    bool b_ret_val=true;
    std::string::size_type ip_start_index = ipstr.find(".in-addr.arpa");

    if (ip_start_index != std::string::npos)
       ipstr.erase(ip_start_index, ipstr.length());
    else{
        ipstr.clear();
        b_ret_val=false;
    }


    if(!ipstr.empty()){

        reverse_ipstr(ipstr);
    }

    return b_ret_val;

}


bool ns::C_DnsManager::reverse_ipstr(std::string& ipstr){

    std::vector<std::string> vec_str{};
    std::stringstream ss(ipstr);

    std::string substr{};

    while (ss.good()) {

        getline(ss, substr, '.');
        vec_str.push_back(substr);

    }

   ipstr.clear();

   if(4==vec_str.size())
   ipstr=vec_str[3]+"."+vec_str[2]+"."+vec_str[1]+"."+vec_str[0];



   return true;

}
