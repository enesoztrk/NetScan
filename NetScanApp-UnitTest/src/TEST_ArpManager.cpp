

#include "gtest/gtest.h"

#include "gmock/gmock.h"
#include "ns_ArpManager.h"
#include "PcapFileDevice.h"
#include "inc/MockPacket.h"

using namespace testing;


class TEST_ArpManager: public ::testing::Test {
public:

   void SetUp( ) {
       // code here will execute just before the test ensues

        ns::Packet_mock_obj= new ns::Mock_Packet;
        std::cout<<"SetUp=================>\n";
   }

   void TearDown( ) {
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be

        delete ns::Packet_mock_obj;
       std::cout<<"TearDown<=================\n";



   }

};
using ::testing::AtLeast;                     // #1
using namespace ns;

TEST_F (TEST_ArpManager, get_host_ip_mac) {


    //Scenario -1
    S_DeviceInfo dev_info{ pcpp::IPAddress("192.168.50.2"),"aa:bb:cc:dd:ee:ff"};
    C_ArpManager dut_arpmanager(dev_info);

    EXPECT_EQ (dev_info, dut_arpmanager.get_host_ip_mac());


    //Scenario -2
    S_DeviceInfo dev_info2{ pcpp::IPAddress("192.162.55.2"),"xx:yy:zz:22:44:11"};
    C_ArpManager dut_arpmanager2(dev_info2);

    EXPECT_EQ (dev_info2, dut_arpmanager2.get_host_ip_mac());



}

using ::testing::NotNull;

#include "TimespecTimeval.h"

TEST_F (TEST_ArpManager, generate_arp_req) {

        pcpp::RawPacket test;
        const uint8_t* a=new uint8_t(1);
        timespec time;
        auto size_rawpacket=2;

        test.setRawData(a,size_rawpacket,time,pcpp::LINKTYPE_IEEE802_15_4_NOFCS,0);


        //Scenario -1 - Return empty dut_rawpacket
        C_ArpManager dut_arpmanager({ pcpp::IPAddress("192.168.50.2"),"aa:bb:cc:dd:ee:ff"});


        //return false
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::EthLayer*>(testing::_))).Times(1).WillOnce(Return(false));
        EXPECT_CALL(*Packet_mock_obj,removeFirstLayer()).Times(1).WillOnce(Return(false));
        EXPECT_CALL(*Packet_mock_obj,computeCalculateFields()).Times(1);

        auto& dut_rawpacket=dut_arpmanager.generate_arp_req<Mock_Packet>(pcpp::IPv4Address("192.168.10.4"));



        EXPECT_NE (test.getRawDataLen(), dut_rawpacket.getRawDataLen());


         //Scenario -2 - Return empty dut_rawpacket
        C_ArpManager dut_arpmanager2({ pcpp::IPAddress("192.168.50.2"),"aa:bb:cc:dd:ee:ff"});



        //return true
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::EthLayer*>(testing::_))).Times(1).WillOnce(Return(true));
        //return false
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::ArpLayer*>(testing::_))).Times(1).WillOnce(Return(false));
        EXPECT_CALL(*Packet_mock_obj,computeCalculateFields()).Times(1);

        EXPECT_CALL(*Packet_mock_obj,removeFirstLayer()).Times(1).WillOnce(Return(false));

        auto& dut_rawpacket2=dut_arpmanager2.generate_arp_req<Mock_Packet>(pcpp::IPv4Address("192.168.10.4"));
        EXPECT_NE (test.getRawDataLen(), dut_rawpacket2.getRawDataLen());



        //Scenario -3 - Return rawpaket which has 2 elements
        C_ArpManager dut_arpmanager3({ pcpp::IPAddress("192.168.50.2"),"aa:bb:cc:dd:ee:ff"});



        //return true
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::EthLayer*>(testing::_))).Times(1).WillOnce(Return(true));
        //return false
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::ArpLayer*>(testing::_))).Times(1).WillOnce(Return(true));
        EXPECT_CALL(*Packet_mock_obj,computeCalculateFields()).Times(1);


        EXPECT_CALL(*Packet_mock_obj, getRawPacket()).WillOnce(Return(&test));

        auto& dut_rawpacket3=dut_arpmanager3.generate_arp_req<Mock_Packet>(pcpp::IPv4Address("192.168.10.4"));
        EXPECT_EQ (test.getRawDataLen(), dut_rawpacket3.getRawDataLen());

}



void arp_resp_testpacket_generation(pcpp::Packet& arp_resp){

    pcpp::Packet test_arp;
    // create a new Ethernet layer
  const pcpp::MacAddress source_mac{"aa:aa:aa:aa:aa:aa"};
  const pcpp::MacAddress dest_mac_eth_broadcast{"dd:dd:dd:dd:dd:dd"};

  pcpp::EthLayer newEthernetLayer( source_mac,dest_mac_eth_broadcast,PCPP_ETHERTYPE_ARP);

  // create a new Arp layer,

  const pcpp::MacAddress dest_mac_arp{dest_mac_eth_broadcast};
  pcpp::ArpLayer newArpLayer( pcpp::ARP_REPLY,
                              source_mac,
                              dest_mac_arp,
                              pcpp::IPv4Address("192.168.50.1"),
                              pcpp::IPv4Address("192.168.50.2"));



  //packet creation to be sent network
  if(!test_arp.addLayer(&newEthernetLayer))
  {

        std::cerr<<"Ethernet Layer Packet Generation has been failed\n";

  }

  if(!test_arp.addLayer(&newArpLayer))
  {
      std::cerr<<"Arp Layer Packet Generation has been failed\n";

  }





  test_arp.computeCalculateFields();

   arp_resp.setRawPacket(test_arp.getRawPacket(),false);

}


TEST_F (TEST_ArpManager, parse_arp_resp) {
    pcpp::Packet incoming_arp_resp{};


    //Arp Packet generation
    C_ArpManager dut_arpmanager({ pcpp::IPAddress("192.168.50.2"),"dd:dd:dd:dd:dd:dd"});

    arp_resp_testpacket_generation(incoming_arp_resp);

   S_DeviceInfo test_dev{pcpp::IPv4Address("192.168.50.1"),std::string{"aa:aa:aa:aa:aa:aa"}};


   S_DeviceInfo ret_val=dut_arpmanager.parse_arp_resp(incoming_arp_resp);
    std::cout<<ret_val<<"\n";
    EXPECT_EQ(test_dev, ret_val);




}








