#ifndef MOCKPACKET_H
#define MOCKPACKET_H
#include <gmock/gmock.h>
#include "ns_Common.h"

namespace ns {

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Invoke;
class Layer;
class EthLayer;
class ArpLayer;
class Mock_Packet : public pcpp::Packet {
 public:

    Mock_Packet()=default;

    //RawPacket& RawPacket::operator=(const RawPacket& other)

    MOCK_METHOD(void,computeCalculateFields,());
    MOCK_METHOD(pcpp::RawPacket*, getRawPacket, (), (const));
   //MOCK_METHOD(pcpp::RawPacket&, operator=, (const pcpp::RawPacket& other));

   pcpp::RawPacket& operator= (const pcpp::RawPacket& other)
   {
    std::cout<<__PRETTY_FUNCTION__<<"\n";
}
   MOCK_METHOD(bool, addLayer, (pcpp::EthLayer* newLayer));
   MOCK_METHOD(bool, addLayer, (pcpp::ArpLayer* newLayer));
   MOCK_METHOD(bool, removeFirstLayer, ());




    Mock_Packet(size_t maxPacketLen): pcpp::Packet(maxPacketLen){


        std::cout<<__PRETTY_FUNCTION__<<"\n";
    }


    // Use this to call Concrete() defined in Foo.
   Mock_Packet* get();

  //MOCK_METHOD(bool, addLayer, (pcpp::ArpLayer* newLayer));

   virtual ~Mock_Packet() = default;


};



Mock_Packet* Packet_mock_obj{nullptr};

Mock_Packet* Mock_Packet::get()
{
      return Packet_mock_obj;
   }

}  // namespace ns
#endif // MOCKPACKET_H
