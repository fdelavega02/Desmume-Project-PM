# DeSmuME - Project PM fork

A fork of the [DeSmuME](https://desmume.org/) Nintendo DS emulator carrying the
embedded multiplayer bridge for **Project PM**, a co-op multiplayer romhack of
Pokémon Platinum.

Based on a DeSmuME 0.9.14 development snapshot.

## What's different from stock DeSmuME

- **Embedded multiplayer bridge** (`desmume/src/frontend/windows/mp_bridge.cpp`):
  a TCP host/join transport built into the emulator. One player hosts, up to
  three more join, and the bridge syncs the romhack's multiplayer mailboxes between instance.
- **Wireless lobby UI**: a small in-emulator window showing connected players,
  names and ping while a session is up.

The sibling melonDS port of the same bridge lives at
[ComicartOlie/melonDS-Project-PM](https://github.com/ComicartOlie/melonDS-Project-PM) (branch
`platinum-mp`).

## Hosting over the internet

One player hosts ("Host LAN Game" in the Multiplayer menu); everyone else
joins with the host's IP. On the same LAN or a VPN (Hamachi, Radmin,
ZeroTier, Tailscale) this works with no setup. To host over the open
internet, three things must all be true on the **host's** side. Joiners
never need any of this:

1. **Router port forward**: forward **TCP 7820** to the host PC.
2. **Windows Firewall**: the router forwards the connection, but Windows
   still has to accept it. The first time you host, the emulator offers to
   add the firewall rule for you (one admin prompt, one time). Say yes.
3. **A real public IP**: if your router's WAN address (in its admin page)
   is different from what whatismyip.com shows, or starts with
   100.64-100.127, your ISP has you behind CGNAT and no amount of port
   forwarding will work. Use a VPN like Hamachi/ZeroTier, or have a friend
   with a real IP host.

## Building

Windows, Visual Studio 2022:

1. Open `desmume/src/frontend/windows/DeSmuME.sln`
2. Configuration **Release Fastbuild**, platform **x64**
3. Build. The exe lands in `desmume/src/frontend/windows/__bins/`

## Branch

All fork work is on **`platinum-mp`**.

## Native Linux port status (fdelavega02 fork)

The `linux-native` branch is the active native-Linux port. Its first milestone
uses the same Project PM mailbox protocol as the Windows build and connects the
bridge to DeSmuME's GTK frame loop. It currently supports harness/environment
startup (`MELONDS_AP=host|join`) while the native GTK Host, Join, and lobby UI
is being ported. Normal users should treat this branch as in development until
the multiplayer flow has been tested between real Linux instances.

## License

DeSmuME is licensed under the **GNU GPL v2**, and so is this fork. All credit for the emulator
itself goes to the DeSmuME team.
