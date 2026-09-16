#pragma once
#include <cstdint>
namespace HuuHungSAMP {
struct Vec3 { float x{}, y{}, z{}; };
class GTAIOSRuntime {
public:
    bool initialize();
    bool isInitialized() const { return initialized_; }
    bool setPlayerPosition(Vec3 position);
    bool setPlayerHeading(float heading);
    bool spawnPlayer(int modelId, Vec3 position, float heading);
private:
    bool initialized_ = false;
};
}
