# HuuHungSAMP-iOS — GTA SA iOS 2.2.21 target

This build now targets the same GTA SA iOS ARM64 version analyzed by the supplied BN_JK research archive: **2.2.21**.

The old 2.02.11 target has been removed from the project configuration.

## Included
- HuuHungSAMP launcher/build project
- Complete supplied BN_JK reverse-engineering study
- Native C++ GameBridge
- SA-MP protocol boundary
- 2.2.21 offset metadata extracted from the supplied research outputs
- Runtime image-slide helper

## Important
The research archive does not contain the original GTA executable. A matching licensed GTA SA iOS 2.2.21 app/binary is still required at build/runtime. The reverse-engineering addresses are not enough to manufacture the game binary itself.

The SA-MP layer is also an integration project: networking, RPC, streaming, sync and engine hooks must be implemented and tested against the actual target binary/server.
