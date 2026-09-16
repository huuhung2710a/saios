# RakNet integration

Build-time source: openmultiplayer/RakNet (SA-MP compatible RakNet 2.52 fork).
The GitHub Actions workflow fetches it with `git clone --depth 1` so the repository does not duplicate the upstream source.

This is networking transport only. SA-MP RPC/packet definitions and GTA iOS runtime hooks remain separate layers.
