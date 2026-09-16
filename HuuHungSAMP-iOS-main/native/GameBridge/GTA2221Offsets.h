#pragma once
#include <cstdint>

// GTA San Andreas iOS ARM64 2.2.21 research metadata.
// Values are image virtual addresses from the supplied BN_JK analysis.
// Convert to runtime addresses with the dyld image slide.
namespace HuuHungSAMP::GTA2221 {
inline constexpr uintptr_t POSITION_HEADING_CANDIDATE = 0x1003e3900;
inline constexpr const char* VERSION = "2.2.21";
}
