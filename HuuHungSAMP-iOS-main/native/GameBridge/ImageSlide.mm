#include "ImageSlide.h"
#include <mach-o/dyld.h>
#include <cstring>
namespace HuuHungSAMP {
uintptr_t gtaImageSlide() {
    const uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = _dyld_get_image_name(i);
        if (!name) continue;
        const char* slash = strrchr(name, '/');
        const char* base = slash ? slash + 1 : name;
        if (strcmp(base, "gta3sa") == 0 || strstr(name, "/gta3sa.app/") != nullptr)
            return static_cast<uintptr_t>(_dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}
uintptr_t gtaRuntimeAddress(uintptr_t imageVMAddress) {
    return imageVMAddress + gtaImageSlide();
}
}
