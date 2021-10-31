#ifndef NS_COMMON_H
#define NS_COMMON_H
#include<string>
#include<unordered_map>
#include "PcapLiveDeviceList.h"
#include<iostream>

namespace ns {

struct common_data_t{

    pcpp::IPAddress scan_ip;
    std::string mac_addr;
    pcpp::Packet   in_packet;
    void* this_ptr;
};

using hostname_t=std::string;

struct S_DeviceInfo {

    pcpp::IPAddress ip;
    std::string mac_addr;



//    S_DeviceInfo& operator=(S_DeviceInfo&& other){


//        ip=other.ip;
//        mac_addr=other.mac_addr;
//        other.ip=pcpp::IPAddress{};
//        other.mac_addr={};
//        std::cout<<__PRETTY_FUNCTION__<<"\n";
//        return *this;
//    }

   S_DeviceInfo()=default;
//    S_DeviceInfo(S_DeviceInfo&& other):ip{other.ip},mac_addr{other.mac_addr}{
//        other.ip=pcpp::IPAddress{};
//        other.mac_addr={};
//    std::cout<<__PRETTY_FUNCTION__<<"\n";
//    }


//   S_DeviceInfo(const S_DeviceInfo& other):ip{other.ip},mac_addr{other.mac_addr}{
//   std::cout<<__PRETTY_FUNCTION__<<"\n";
//   }

//    S_DeviceInfo& operator=(const S_DeviceInfo& other){
//        ip=other.ip;
//        mac_addr=other.mac_addr;
//        std::cout<<__PRETTY_FUNCTION__<<"\n";
//        return *this;
//    }


    S_DeviceInfo(const pcpp::IPAddress& ip_param,const std::string& mac_param):ip{ip_param},mac_addr{mac_param}
       {
         //   std::cout<<__PRETTY_FUNCTION__<<"\n";
       }


    // `operator==` is required to compare keys in case of a hash collision
       bool operator==(const S_DeviceInfo &p) const {

           return  mac_addr == p.mac_addr;
       }




       friend std::ostream& operator<<(std::ostream& os,const S_DeviceInfo& dev_info);

};
class hash_func {
public:


    // as hash function.
     size_t operator()(const S_DeviceInfo& p) const
    {

         //std::size_t h1 = std::hash<std::string>{}(p.ip.toString());
         std::size_t h2 = std::hash<std::string>{}(p.mac_addr);


      //return h1 ^ (h2 << 1);
         return h2;
    }
};

using dev_info_t=std::unordered_map<S_DeviceInfo,hostname_t,hash_func>;


inline std::ostream& operator<<(std::ostream& os,const S_DeviceInfo& dev_info){



    return os<<"[Mac addr= "<<dev_info.mac_addr<<", Ip= "<<dev_info.ip.toString()<<" ]";


}



}
#endif // NS_COMMON_H
