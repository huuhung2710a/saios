#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace HuuHungSAMP {
struct SampServer { std::string host; uint16_t port = 7777; };
class SampProtocol {
public:
    explicit SampProtocol(SampServer server) : server_(std::move(server)) {}
    std::vector<uint8_t> buildConnectRequest(const std::string& nickname) const;
    bool handleIncoming(const uint8_t* data, size_t size);
private:
    SampServer server_;
};
}
