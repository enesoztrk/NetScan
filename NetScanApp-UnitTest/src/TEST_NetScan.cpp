
#include "gtest/gtest.h"

#include "gmock/gmock.h"
#include "PcapFileDevice.h"
#include "inc/MockArpManager.h"
#include "ns_NetScan.h"
#include "ns_DnsManager.h"
using namespace testing;

using ::testing::AtLeast;                     // #1
using namespace ns;

class TEST_NetScan: public ::testing::Test {
public:

   void SetUp( ) {
       // code here will execute just before the test ensues

     //   ns::Packet_mock_obj= new ns::Mock_Packet;
        std::cout<<"SetUp\n";
   }

   void TearDown( ) {
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be

       // delete ns::Packet_mock_obj;
       std::cout<<"TearDown\n";



   }

};




TEST_F (TEST_NetScan, test1) {

//     S_DeviceInfo gateway_mac_ip{ pcpp::IPAddress("192.168.1.1"),std::string("")};


//     MockC_ArpManager* dynamic_arp=new MockC_ArpManager(gateway_mac_ip,gateway_mac_ip);

//    CT_NtwrkScan<MockC_ArpManager,ns::C_DnsManager> netscan("192.168.10.10");

//    auto& param=netscan.get_arp_instance();

//    std::cout<<"hello\n";

}
