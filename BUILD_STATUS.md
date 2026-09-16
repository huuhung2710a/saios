# HuuHungSAMP iOS 2.2.21 build status

This repository is the integration scaffold for GTA SA iOS 2.2.21 + BN_JK reverse-engineering data + SA-MP-compatible RakNet.

## Important
- The BN_JK archive contains the Ghidra analysis database and reports, not a standalone `gtasa` Mach-O or the complete GTA asset bundle.
- The workflow can validate/compile the HuuHung native layer and fetch the openmultiplayer RakNet source.
- A genuinely playable IPA still requires the authorized GTA SA 2.2.21 application binary/assets and target-specific runtime patching/signing.
- `CODE_SIGNING_ALLOWED=NO` produces an unsigned archive; it is not directly installable on a normal iPhone.

## Goal
Keep the project buildable at every step rather than hiding missing runtime inputs behind a fake IPA.
