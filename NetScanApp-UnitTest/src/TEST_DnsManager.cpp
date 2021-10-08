


#include "gtest/gtest.h"

#include "gmock/gmock.h"
#include "PcapFileDevice.h"
#include "ns_DnsManager.h"
#include "inc/MockPacket.h"
using namespace testing;

using ::testing::AtLeast;                     // #1
using namespace ns;

class TEST_DnsManager: public ::testing::Test {
public:

   void SetUp( ) {
       // code here will execute just before the test ensues

        ns::Packet_mock_obj= new ns::Mock_Packet;
        std::cout<<"SetUp\n";
   }

   void TearDown( ) {
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be

        delete ns::Packet_mock_obj;
       std::cout<<"TearDown\n";



   }

};


#define INPUT_FILE "/home/enes/home_projects/Pcap++_example/Project_pcap/example/dns_example.pcapng"
TEST_F (TEST_DnsManager, dns) {



    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(INPUT_FILE);

    // verify that a reader interface was indeed created
    if (reader == NULL)
    {
        std::cerr << "Cannot determine reader for file type" << std::endl;

    }

    // open the reader for reading
    if (!reader->open())
    {
        std::cerr << "Cannot open input.pcap for reading" << std::endl;

    }

    // set a BPF filter for the reader - only packets that match the filter will be read
    pcpp::PortFilter protocolDNSPortFilter(53,pcpp::SRC);

        if (!reader->setFilter(protocolDNSPortFilter))
        {
            std::cerr << "Cannot set filter for file reader" << std::endl;

        }



        pcpp::RawPacket rawPacket;
        pcpp::Packet parsedPacket;
        S_DeviceInfo gateway_mac_ip{ pcpp::IPAddress("192.168.1.1"),std::string("")};
        C_DnsManager dut_dnsmanager({ pcpp::IPAddress("192.168.50.2"),"dd:dd:dd:dd:dd:dd"},gateway_mac_ip);
        // a while loop that will continue as long as there are packets in the input file
        // matching the BPF filter

       std::pair<std::string, pcpp::IPAddress> ret_val2;

        while (reader->getNextPacket(rawPacket))
        {

              parsedPacket.setRawPacket(&rawPacket,false);

           auto ret_val= dut_dnsmanager.parse_dns_resp(parsedPacket);

           if(ret_val.first!=""){
               ret_val2=ret_val;
               std::cout<<"Host name: "<<ret_val.first<<"\n";
               std::cout<<"IP addr: "<<ret_val.second.toString()<<"\n";
           }


        }


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



    std::cout<<"x mac "<< x.begin()->first.mac_addr<<"\n";
    std::cout<<"x host  "<< x.begin()->second<<"\n";


    dut_dnsmanager.generate_dns_req(TEST);



}
