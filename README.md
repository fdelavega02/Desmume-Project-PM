# DeSmuME - Project PM fork

A fork of the [DeSmuME](https://desmume.org/) Nintendo DS emulator carrying the
embedded multiplayer bridge for **Project PM**, a co-op multiplayer romhack of
Pokémon Platinum.

Based on a DeSmuME 0.9.14 development snapshot.

This is an in-progress community fork actively maintained by
**M4doesstuff** and **Hermy**.

## What's different from stock DeSmuME

- **Embedded multiplayer bridge** (`desmume/src/frontend/windows/mp_bridge.cpp`):
  a TCP host/join transport built into the emulator. One player hosts, up to
  three more join, and the bridge syncs the romhack's multiplayer mailboxes between instance.
- **Wireless lobby UI**: a small in-emulator window showing connected players,
  names and ping while a session is up.

The upstream sibling melonDS port of the same bridge lives at
[ComicartOlie/melonDS-Project-PM](https://github.com/ComicartOlie/melonDS-Project-PM) (branch
`platinum-mp`).

For native Linux melonDS builds, use [M4doesstuff's Project PM Linux
port](https://github.com/fdelavega02/melonDS-Project-PM), on its default
`linux-native` branch. It provides a Linux x86_64 AppImage through its
[releases](https://github.com/fdelavega02/melonDS-Project-PM/releases).

## Hosting over the internet

One player hosts ("Host LAN Game" in the Multiplayer menu); everyone else
joins with the host's IP. On the same LAN or a VPN (Hamachi, Radmin,
ZeroTier, Tailscale) this works with no setup. To host over the open
internet, three things must all be true on the **host's** side. Joiners
never need any of this:

1. **Router port forward**: forward **TCP 7820** to the host PC.
2. **Host firewall**: the router forwards the connection, but the host OS must
   still accept it. Windows builds offer to add a firewall rule. On Linux,
   allow **TCP 7820** using your chosen firewall manager.
3. **A real public IP**: if your router's WAN address (in its admin page)
   is different from what whatismyip.com shows, or starts with
   100.64-100.127, your ISP has you behind CGNAT and no amount of port
   forwarding will work. Use a VPN like Hamachi/ZeroTier, or have a friend
   with a real IP host.

## Building on Windows

Windows, Visual Studio 2022:

1. Open `desmume/src/frontend/windows/DeSmuME.sln`
2. Configuration **Release Fastbuild**, platform **x64**
3. Build. The exe lands in `desmume/src/frontend/windows/__bins/`

## Branches

Upstream Project PM development is on **`platinum-mp`**. This fork's native
Linux work is on **`linux-native`**, which is also its default branch.

## Native Linux port status

The `linux-native` branch is the active native-Linux port. It uses the same
Project PM mailbox protocol as the Windows build and connects the bridge to
DeSmuME's GTK frame loop. The **Multiplayer** menu provides native **Host LAN
Game**, **Join LAN Game**, and **Disconnect** controls. The live player/ping
lobby is still being ported, and the multiplayer flow needs real two-instance
testing before this branch is considered a release.

Build on Arch-based distributions:

```sh
sudo pacman -S --needed meson ninja gtk3 sdl2 libpcap
meson setup build-linux desmume/src/frontend/posix
ninja -C build-linux
./build-linux/gtk/desmume
```

Hosts listen on TCP port 7820. For Internet play, open that port in the host's
firewall/router, or use a VPN such as Tailscale.

## License

DeSmuME is licensed under the **GNU GPL v2**, and so is this fork. All credit for the emulator
itself goes to the DeSmuME team.
