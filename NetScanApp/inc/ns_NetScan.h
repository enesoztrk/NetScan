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
#include <exception>
#include "ns_SM.h"
#include <unistd.h>

namespace ns {

//TODO: this will be local variable


template<typename T=C_ArpManager, typename U=C_DnsManager>
class CT_NtwrkScan{

public:
    CT_NtwrkScan()=delete;



    CT_NtwrkScan(const pcpp::IPAddress& ethif_ip){

        // find the interface by IP address
      dev.reset(pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(ethif_ip));

      if (dev == nullptr)
        {
            std::cerr<<"Cannot find interface with IPv4 address of "<<ethif_ip.toString()<<"\n";
            throw std::invalid_argument{"Cannot find network interface from IP addr"};

        }


        init_dev_params(dev);


        if (!dev->open(pcap_config))
        {
            std::cerr<<"Cannot open device\n";
            throw std::invalid_argument{"Cannot open the device"};

        }

        set_ntwrk_filter();

        common_data.set_this_ptr(this);

      //  common_data.this_ptr=this;


    }

    CT_NtwrkScan(const std::string& ethif_name){

         dev.reset(pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ethif_name));
          if (dev == nullptr)
          {
              std::cerr<<"Cannot find interface  "<<ethif_name<<"\n";
             throw std::invalid_argument{"Cannot find network interface from netif name"};
          }

       init_dev_params(dev);

       if (!dev->open(pcap_config))
       {
           std::cerr<<"Cannot open device\n";
           throw std::invalid_argument{"Cannot open the device"};

       }
       set_ntwrk_filter();
    }


    bool set_ntwrk_filter(){
        // set a BPF filter for the reader - only packets that match the filter will be read
         pcpp::ProtoFilter protocolArpFilter(pcpp::ARP);
        pcpp::PortFilter protocolDNSPortFilter(53,pcpp::SRC);
         pcpp::PortFilter protocolmDNSPortFilter(5353,pcpp::SRC);


        // create an OR filter to combine both filters - capture only ARP or DNS packets
        pcpp::OrFilter  OrFilter;
        OrFilter.addFilter(&protocolArpFilter);
        OrFilter.addFilter(&protocolDNSPortFilter);
        OrFilter.addFilter(&protocolmDNSPortFilter);

            if (!dev->setFilter(OrFilter))
            {
                std::cerr << "Cannot set filter for " <<dev->getName()<< std::endl;
                throw std::invalid_argument{"filter cannot applied for "+dev->getName()};
            }

            return true;
    }

    bool start(){

              NetScan_SM::fsm_handle::register_callback(SM_Inactive_state_cb, NetScan_SM::States::INACTIVE);
              NetScan_SM::fsm_handle::register_callback(SM_Arpmsg_send_state_cb, NetScan_SM::States::ARP_MSG_SEND);
              NetScan_SM::fsm_handle::register_callback(SM_Arpmsg_parse_state_cb, NetScan_SM::States::ARP_MSG_PARSE);
              NetScan_SM::fsm_handle::register_callback(SM_Dnsmsg_send_state_cb, NetScan_SM::States::DNS_MSG_SEND);
              NetScan_SM::fsm_handle::register_callback(SM_Dnsmsg_parse_state_cb, NetScan_SM::States::DNS_MSG_PARSE);
              NetScan_SM::fsm_handle::register_callback(SM_CommTimeout_state_cb, NetScan_SM::States::COMM_TIMEOUT);



        //SM start
        NetScan_SM::fsm_handle::start();




        //start capture
        start_packet_capture();

    }
    bool start_packet_capture(){
        bool ret_val=false;


            // start capturing packets. All packets will be added to the packet vector

        if(dev->isOpened()){


            // start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
                if(dev->startCapture(onPacketArrives, NULL))//if(  dev->startCapture(packetVec))//if(dev->startCapture(onPacketArrives, NULL))
                    ret_val=true;

        }

        return ret_val;

    }
    bool stop_packet_capture(){


        if(dev->captureActive()){
            dev->stopCapture();
        }

        return true;
    }


    bool stop();

    const dev_info_t& get_device_list()const{

        return dev_table;

    }

    bool set_ip_range(const std::string& low_bound_ip,const std::string& high_bound_ip ){

        bool ret_val=true;
        uint8_t ip_bytes[4]{};
        low_bound_ip_addr=pcpp::IPv4Address(low_bound_ip);
        high_bound_ip_addr=pcpp::IPv4Address(high_bound_ip);
        



      for(auto i=0;i<3;++i){

           if (low_bound_ip_addr.toBytes()[i]!=low_bound_ip_addr.toBytes()[i])
                    ret_val=false;

      }

        if(ret_val==true && low_bound_ip_addr.toBytes()[3]<high_bound_ip_addr.toBytes()[3]){
            ip_bytes[0]=low_bound_ip_addr.toBytes()[0];
            ip_bytes[1]=low_bound_ip_addr.toBytes()[1];
            ip_bytes[2]=low_bound_ip_addr.toBytes()[2];

            //reservation for number of ip address
            scan_ip_vec.reserve(high_bound_ip_addr.toBytes()[3]-low_bound_ip_addr.toBytes()[3]);
        }
        else
            ret_val=false;

         /*First of all, arp req will be sent to learn gateway mac addr*/
         scan_ip_vec.push_back(dev->getDefaultGateway());

        for(auto i=low_bound_ip_addr.toBytes()[3];(ret_val==true && i<=high_bound_ip_addr.toBytes()[3] );++i){

            ip_bytes[3]=i;

            /*do not send arp req to our ip addr*/
            if(i!=dev->getIPv4Address().toBytes()[3]){

                  scan_ip_vec.push_back(pcpp::IPv4Address(ip_bytes));
            }


        }

           for(auto& i:scan_ip_vec)
             scan_ip_vec.push_back(i);


           for(auto& i:scan_ip_vec)
             scan_ip_vec.push_back(i);


        return ret_val;
    }


    void run(){



        
        if(!scan_ip_vec.empty() ){

                   common_data.set_common_data(*scan_ip_vec.begin());
                    bool ret_val=false;
                    NetScan_SM::fsm_handle::invoke_ArpMsgsend_state(ret_val,common_data);
                                if(ret_val){

                                       scan_ip_vec.erase(scan_ip_vec.begin());
                                }



        }
        else{
            std::cout<<"===Device list===\n";
            for(auto& iter:dev_table ){

                std::cout<<"IPaddr: "<<iter.first.ip.toString()<<" Mac addr: "<<iter.first.mac_addr<<"\n";


            }
            exit(1);
        }


        in_data_dispatch();

        NetScan_SM::fsm_handle::dispatch(NetScan_SM::Timer_check(1));

    }


    bool find_ip_in_device_list(const pcpp::IPAddress& ip){

            bool ret_val=false;
        auto is_ip_same = [&ip](auto& i){ return i.first.ip==ip; };

        decltype (dev_table.begin()) result1 = std::find_if(begin(dev_table), end(dev_table), is_ip_same);

          if(result1!=end(dev_table)){
              // result1->second=ret_val2.first;
              std::cout << "found\n";
              ret_val=true;
          }

          return ret_val;

    }

    auto find_ip_in_device_list_return(const pcpp::IPAddress& ip) {

           decltype (dev_table.begin()) ret_val{nullptr};
           auto is_ip_same = [&ip](auto& i){ return i.first.ip==ip; };

             auto result1 = std::find_if(begin(dev_table), end(dev_table), is_ip_same);

             if(result1!=end(dev_table)){
                 // result1->second=ret_val2.first;
                 std::cout << "found\n";
                // ret_val=true;
                 ret_val=result1;
             }

             return ret_val;

       }


    bool sendpacket(pcpp::RawPacket& packet){

        return  dev->sendPacket(packet);
    }

    T& get_arp_instance(){
        return *c_arp;
    }

    U& get_dns_instance(){
        return *c_dns;
    }

    static std::vector<pcpp::RawPacket>&  get_packet_vec(){

               return packetVec;
    }

    static bool set_raw_packet(pcpp::RawPacket& packet){

                packetVec.push_back(packet);

                return true;
    }

    static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
    {
            //TODO: mutex lock will be here.
        // create an empty packet vector object
      //  packetVec.push_back(*packet);
          set_raw_packet(*packet);

        //TODO: mutex unlock will be here
        }



private:
    //create an empty packet vector object
    static inline  std::vector<pcpp::RawPacket> packetVec{};
   //pcpp::RawPacketVector packetVec{};
    std::vector<pcpp::IPv4Address> scan_ip_vec{};
    common_data_t common_data{};
    std::unique_ptr<pcpp::PcapLiveDevice> dev{nullptr};
    pcpp::IPv4Address low_bound_ip_addr{};
    pcpp::IPv4Address high_bound_ip_addr{};
    dev_info_t dev_table{};

    S_DeviceInfo gateway_mac_ip{ pcpp::IPAddress(""),std::string("")};
    S_DeviceInfo netif_mac_ip{ pcpp::IPAddress(""),std::string("")};
    std::unique_ptr<T> c_arp{nullptr};
    std::unique_ptr<U> c_dns{nullptr};

    const pcpp::PcapLiveDevice::DeviceConfiguration pcap_config{pcpp::PcapLiveDevice::DeviceMode::Promiscuous,0,0,pcpp::PcapLiveDevice::PcapDirection::PCPP_IN,0};

    bool add_dev_list(const pcpp::MacAddress&);//add mac address
    bool add_dev_list(const std::string&);//add dns hostname


    bool init_dev_params( std::unique_ptr<pcpp::PcapLiveDevice>& dev){

        //network interface ip and mac addresses definition
        netif_mac_ip.ip=dev->getIPv4Address();
        netif_mac_ip.mac_addr=dev->getMacAddress().toString();


        gateway_mac_ip.ip=dev->getDefaultGateway();
         auto dns=   dev->getDnsServers();

        if (c_arp == nullptr)
                c_arp.reset(new T(netif_mac_ip,gateway_mac_ip));
         else
                throw std::invalid_argument{"c_arp variable is already allocated"};


        if (c_dns == nullptr)
        c_dns.reset(new U(netif_mac_ip,gateway_mac_ip));
         else
          throw std::invalid_argument{"c_dns variable is already allocated"};

        return true;
    }


    void in_data_dispatch(){


        if(get_packet_vec().size()!=0){

                pcpp::Packet temp_packet(&(*get_packet_vec().begin()));



                if(temp_packet.isPacketOfType(pcpp::ARP)){
                    pcpp::ArpLayer* arpLayer =
                           temp_packet.getLayerOfType<pcpp::ArpLayer>();

//                    if(!find_ip_in_device_list(arpLayer->getSenderIpAddr())){

//                    }

                    common_data.set_common_data(arpLayer->getSenderIpAddr(),std::string(""),temp_packet);



                    if( arpLayer->getSenderIpAddr().isValid()){
                         NetScan_SM::fsm_handle::invoke_ArpMsgRecv_state(common_data);

                    }


                }
                else if(temp_packet.isPacketOfType(pcpp::DNS))
                {

                    pcpp::IPLayer* ipLayer =
                           temp_packet.getLayerOfType<pcpp::IPLayer>();



                    //TODO: mdns feature will be added for autoretive server
                    //https://datatracker.ietf.org/doc/html/rfc6762#page-5
                    if(ipLayer->getSrcIPAddress()==gateway_mac_ip.ip && ipLayer->getDstIPAddress()==netif_mac_ip.ip){

                        //FIXME: will be set data
                        common_data.set_common_data(pcpp::IPAddress(),std::string(""),temp_packet);


                        NetScan_SM::fsm_handle::invoke_DnsMsgRecv_state(common_data);

                    }



                }


                get_packet_vec().erase(get_packet_vec().begin());

        }

    }



  static  bool SM_Inactive_state_cb(int i,void* ptr){
        static bool is_init=true;


      ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);
       CT_NtwrkScan<> * this_ptr= static_cast< CT_NtwrkScan<> *>(common_data->get_this_ptr());


       common_data->set_common_data();


    std::cout<<"SM_Inactive_state_cb\n";
    return true;
    }


   static   bool SM_Arpmsg_send_state_cb(int i,void* ptr){

       ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);
        CT_NtwrkScan<> * this_ptr= static_cast< CT_NtwrkScan<> *>(common_data->get_this_ptr());

          //  for(auto i=0;i<3";i++)
            this_ptr->sendpacket(this_ptr->c_arp->generate_arp_req(common_data->get_scan_ip(). getIPv4()));


    std::cout<<"SM_Arpmsg_send_state_cb: "<< common_data->get_scan_ip().toString()<< "\n";
    return true;
    }

   static   bool SM_Arpmsg_parse_state_cb(int i,void* ptr){
       ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);
        CT_NtwrkScan<> * this_ptr= static_cast< CT_NtwrkScan<> *>(common_data->get_this_ptr());
        bool b_ret_val=false;
        S_DeviceInfo response=  this_ptr->c_arp->parse_arp_resp(common_data->get_in_packet());




        if(response.ip==common_data->get_scan_ip() ){
            common_data->set_common_data(response.ip,response.mac_addr);
            //common_data->mac_addr=response.mac_addr;
            if(!this_ptr->find_ip_in_device_list(response.ip))
            this_ptr->dev_table[response]="";
            b_ret_val=true;
        }


        if(response.ip==this_ptr->gateway_mac_ip.ip)
            this_ptr->gateway_mac_ip.mac_addr=response.mac_addr;


      std::cout<<"SM_Arpmsg_parse_state_cb, " << response.ip.toString()<<" ,"<< response.mac_addr<<"\n";
    return b_ret_val;
    }


   static   bool SM_Dnsmsg_send_state_cb(int i,void* ptr){
       ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);
        CT_NtwrkScan<> * this_ptr= static_cast< CT_NtwrkScan<> *>(common_data->get_this_ptr());

        this_ptr->sendpacket(this_ptr->c_dns->generate_dns_req(S_DeviceInfo(common_data->get_scan_ip(),common_data->get_mac_addr())));
    std::cout<<"SM_Dnsmsg_send_state_cb\n";
    return true;
    }


  static    bool SM_Dnsmsg_parse_state_cb(int i,void* ptr){
      ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);
       CT_NtwrkScan<> * this_ptr= static_cast< CT_NtwrkScan<> *>(common_data->get_this_ptr());

       const auto response=this_ptr->c_dns->parse_dns_resp(common_data->get_in_packet());

       if(response.second!=pcpp::IPAddress(""))
       auto iter=this_ptr->find_ip_in_device_list_return(response.second);



    std::cout<<"SM_Dnsmsg_parse_state_cb " <<response.first<<" ," << response.second.toString()<<"\n";
    return true;
    }

  static    bool SM_CommTimeout_state_cb(int i,void* ptr){

 ns::common_data_t* common_data=static_cast<ns::common_data_t*>(ptr);

 std::cout<<"SM_CommTimeout_state_cb, " << common_data->get_scan_ip().toString()<<"\n";



  }

};

using C_NtwrkScan=CT_NtwrkScan<>;

}

#endif // NS_NETSCAN_H
