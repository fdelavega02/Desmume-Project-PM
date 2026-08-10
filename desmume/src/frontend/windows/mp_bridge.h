/*
    mp_bridge.h — fork-embedded mailbox bridge + test autopilot for the
    Pokémon Platinum multiplayer romhack.

    DeSmuME analog of the melonDS fork's BridgePump (EmuThread.cpp): when the
    loaded ROM publishes its discovery block (signature 0xCAFE1234/0x5678CAFE
    in main RAM) and the bridge control block (discovery slot 31), this pump
    syncs the ROM's multiplayer mailboxes across a TCP link at frame rate.
    The emulated radio is never touched.

    Transport: direct TCP (host listens on 7820, joiner connects), carrying
    the same tagged bundles the melonDS fork ships over its ENet channel:
        [u16 len LE] [tag u8][role u8][size u16 LE][payload]
        tag 1 = block+ow (every frame), 2 = party (on change), 3 = pkt (on change)

    Configuration is env-driven (kept name-compatible with the melonDS fork so
    the existing campaign harness drives both emulators unchanged):
        MELONDS_AP=host|join        enable bridge + autopilot; pick role
        MELONDS_AP_IP=<ip>          join target (default 127.0.0.1)
        MELONDS_AP_PATTERN=...      walk|ugclient|ughost test patterns
        MELONDS_AP_HOLD=1           bridge only, no scripted input
*/

#ifndef MP_BRIDGE_H
#define MP_BRIDGE_H

// Reads the env vars above and (if set) configures + arms the bridge.
// Call once from _main after WSAStartup.
void MpBridge_InitFromEnv();

// Per-frame pump: discovery scan, MpBridgeCtl handshake, mailbox TX/RX.
// Call inside StepRunLoop_Core's { Lock lock; } block, right after
// NDS_exec<false>() returns (main RAM is coherent, emulation halted).
void MpBridge_Pump();

// Scripted test input: overrides the in-processing UserInput. Call between
// NDS_beginProcessingInput()/NDS_endProcessingInput(), after input_process().
void MpAp_OverrideInput();

// Close sockets / stop the listener. Call before WSACleanup.
void MpBridge_Shutdown();

// Frontend-neutral session controls. The GTK frontend uses these directly;
// the Windows frontend continues to use its existing Win32 menu callbacks.
bool MpBridge_StartHost(const char* name);
bool MpBridge_Join(const char* name, const char* ip);
void MpBridge_Stop();
bool MpBridge_IsActive();

// --- LAN lobby UI (Win32) ---
struct HWND__; typedef struct HWND__* HWND;
struct HMENU__; typedef struct HMENU__* HMENU;
void MpBridge_InstallMenu(HWND mainWnd);          // append the Multiplayer menu
bool MpBridge_HandleCommand(unsigned int id);     // WM_COMMAND; true if ours
void MpBridge_OnInitPopup(HMENU menu);            // WM_INITMENUPOPUP: refresh host list


#endif
