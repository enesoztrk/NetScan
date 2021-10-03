

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
        std::cout<<"SetUp\n";
   }

   void TearDown( ) {
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be

        delete ns::Packet_mock_obj;
       std::cout<<"TearDown\n";



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


      //  EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::ArpLayer*>(testing::_))).Times(1).WillOnce(Return(true));
        //return false
        EXPECT_CALL(*Packet_mock_obj,addLayer(Matcher<pcpp::EthLayer*>(testing::_))).Times(1).WillOnce(Return(false));
        EXPECT_CALL(*Packet_mock_obj,removeFirstLayer()).Times(1).WillOnce(Return(false));
        EXPECT_CALL(*Packet_mock_obj,computeCalculateFields()).Times(1);

        auto& dut_rawpacket=dut_arpmanager.generate_arp_req<Mock_Packet>(pcpp::IPv4Address("192.168.10.4"));


    //    EXPECT_CALL(*Packet_mock_obj,getRawPacket()).Times(1).WillOnce(Return(nullptr));

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








