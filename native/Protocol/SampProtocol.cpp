#include "SampProtocol.h"
namespace HuuHungSAMP {
std::vector<uint8_t> SampProtocol::buildConnectRequest(const std::string& nickname) const {
    // Protocol implementation is isolated here for the exact SA-MP/RakNet target.
    return std::vector<uint8_t>(nickname.begin(), nickname.end());
}
bool SampProtocol::handleIncoming(const uint8_t* data, size_t size) {
    return data != nullptr && size != 0;
}
}
