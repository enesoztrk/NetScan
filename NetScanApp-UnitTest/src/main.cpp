#include "inc/MockArpManager.h"
#include "inc/MockDnsManager.h"
#include "../NetScanApp/inc/ns_NetScan.h"
#include "gtest/gtest.h"

#include "gmock/gmock.h"
//#include "new.h"

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    return ret;
}

class TEST: public ::testing::Test {
public:

   void SetUp( ) {
       // code here will execute just before the test ensues



   }

   void TearDown( ) {
       // code here will be called just after the test completes
       // ok to through exceptions from here if need be





   }

};
using ::testing::AtLeast;                     // #1
using namespace ns;

TEST_F (TEST, ITcpIpctor) {

    CT_NtwrkScan<MockC_ArpManager,MockC_DnsManager> ntwrk_scan;                          // #2


    EXPECT_CALL(ntwrk_scan.get_arp_instance(), parse_arp_resp())              // #3
          .Times(AtLeast(1));

    ntwrk_scan.scan_start();
}
