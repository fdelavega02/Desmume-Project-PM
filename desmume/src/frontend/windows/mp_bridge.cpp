/*
    mp_bridge.cpp — fork-embedded mailbox bridge + test autopilot.
    See mp_bridge.h for the overview.  This is a port of the melonDS fork's
    BridgePump + apApply (melonDS/src/frontend/qt_sdl/EmuThread.cpp), with the
    ENet LAN transport replaced by a direct non-blocking TCP pair and input
    injection going through NDS_getProcessingUserInput() instead of a key mask.

    Everything runs on the emulation thread; sockets are non-blocking and
    drained/flushed with bounded work per frame (DeSmuME's run loop is
    single-threaded — a blocking call here would freeze emulation).
*/

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef int SOCKET;
typedef int BOOL;
typedef unsigned long u_long;
static const SOCKET INVALID_SOCKET = -1;
static const int SOCKET_ERROR = -1;
static const BOOL TRUE = 1;
static const int WSAEWOULDBLOCK = EWOULDBLOCK;
static const int WSAEINPROGRESS = EINPROGRESS;
static const int WSAEISCONN = EISCONN;
static inline int WSAGetLastError() { return errno; }
static inline int closesocket(SOCKET s) { return close(s); }
static inline int ioctlsocket(SOCKET s, long cmd, u_long* value) { return ioctl(s, cmd, value); }
static inline unsigned long GetTickCount()
{
    using namespace std::chrono;
    return (unsigned long)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include <vector>
#include <string>

#include "MMU.h"
#include "mem.h"
#include "NDSSystem.h"
#include "armcpu.h"

#include "mp_bridge.h"

// ---------------------------------------------------------------------------
// Emulated RAM accessors (retail DS: mask 0x3FFFFF) — melonDS apRd*/apWr8/apPtr.
// Direct array access on purpose: mailboxes are .bss data, never executed, so
// no JIT invalidation or IO dispatch is wanted (same as the melonDS fork).
// ---------------------------------------------------------------------------
static inline u32 apRd32(u32 a) { return T1ReadLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32); }
static inline u16 apRd16(u32 a) { return T1ReadWord(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK16); }
static inline s16 apRd16s(u32 a) { return (s16)apRd16(a); }
static inline u8  apRd8(u32 a) { return T1ReadByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK); }
static inline void apWr8(u32 a, u8 v) { T1WriteByte(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK, v); }
static inline u8* apPtr(u32 a) { return &MMU.MAIN_MEM[a & _MMU_MAIN_MEM_MASK]; }
static inline void apWr32(u32 a, u32 v) { T1WriteLong(MMU.MAIN_MEM, a & _MMU_MAIN_MEM_MASK32, v); }

// ---------------------------------------------------------------------------
// Transport: one non-blocking TCP link (host listens :7820, joiner connects).
// Frame: [u16 len LE][payload]; payload = the melonDS bridge bundle.
// ---------------------------------------------------------------------------
namespace
{

const int MP_PORT = 7820;
const u32 MP_MAX_FRAME = 8192;

// ---------------------------------------------------------------------------
// Windows Firewall helper for hosting.  Router port-forwarding alone can't
// make a host reachable: the inbound connection must also pass this PC's own
// firewall, and declining the first-launch security alert leaves a permanent
// block rule for the exe ("I forwarded 7820 and my friend still can't join").
// The "Allow" prompt also defaults to private networks only, which drops
// peers when the home network is profiled Public.  On host start we check
// the world-readable firewall-rules registry key; if our rule is absent we
// ASK the player, then run the standard netsh repair visibly with one
// admin prompt (same repair the PlatinumMP launcher's Fix-Firewall button
// does for its own exe).
// ---------------------------------------------------------------------------
#ifdef _WIN32
const wchar_t* MP_FW_RULE = L"DeSmuME (Project PM)";

static void mpFwLower(std::wstring& s)
{
    for (size_t i = 0; i < s.size(); i++) s[i] = towlower(s[i]);
}

static bool mpFwRulePresent(const wchar_t* exe)
{
    HKEY k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        0, KEY_READ, &k) != ERROR_SUCCESS) return false;

    // rule values are pipe-delimited token strings: v2.x|Action=Allow|...|App=path|...|Name=...|
    std::wstring wantName = L"|name="; wantName += MP_FW_RULE; wantName += L"|";
    std::wstring wantApp  = L"|app=";  wantApp  += exe;        wantApp  += L"|";
    mpFwLower(wantName); mpFwLower(wantApp);

    bool found = false;
    wchar_t name[256]; BYTE data[4096];
    for (DWORD i = 0; !found; i++)
    {
        DWORD nl = 256, dl = sizeof(data) - 2, type = 0;
        LONG r = RegEnumValueW(k, i, name, &nl, NULL, &type, data, &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS || type != REG_SZ) continue;
        data[dl] = 0; data[dl + 1] = 0;
        std::wstring v((const wchar_t*)data);
        mpFwLower(v);
        found = v.find(wantName) != std::wstring::npos
             && v.find(wantApp)  != std::wstring::npos
             && v.find(L"|action=allow|") != std::wstring::npos
             && v.find(L"|dir=in|")       != std::wstring::npos
             && v.find(L"|active=true|")  != std::wstring::npos;
    }
    RegCloseKey(k);
    return found;
}

static void mpEnsureFirewall()
{
    static bool once = false;
    if (once) return;
    once = true;
    if (getenv("MELONDS_AP")) return;   // automated harness instances: no prompts

    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    if (!n || n >= MAX_PATH) return;

    if (mpFwRulePresent(exe)) { printf("[BR] firewall rule ok\n"); return; }

    // Ask the player first, and run the repair in a visible window so
    // nothing about this is silent.
    if (MessageBoxW(NULL,
        L"To let friends join your hosted game, Windows Firewall needs an\n"
        L"inbound rule for this emulator (without it, players outside your\n"
        L"PC usually can't connect even with the port forwarded).\n\n"
        L"Add the rule now?  Windows will show one administrator prompt.",
        L"Project PM - enable hosting", MB_YESNO | MB_ICONQUESTION) != IDYES)
    {
        printf("[BR] firewall rule declined by user\n");
        return;
    }

    wchar_t args[1200];
    swprintf(args, 1200,
        L"/c netsh advfirewall firewall delete rule name=all program=\"%ls\" & "
        L"netsh advfirewall firewall add rule name=\"%ls\" dir=in action=allow "
        L"program=\"%ls\" enable=yes profile=any", exe, MP_FW_RULE, exe);
    HINSTANCE rc = ShellExecuteW(NULL, L"runas", L"cmd.exe", args, NULL, SW_SHOWMINNOACTIVE);
    printf("[BR] firewall rule %s\n",
        ((INT_PTR)rc > 32) ? "repair launched" : "not added (admin prompt declined)");
}
#else
// Linux distributions differ on firewall ownership (ufw, firewalld, nftables).
// Never mutate host firewall rules silently; document TCP 7820 in the GTK UI.
static void mpEnsureFirewall() {}
#endif

struct MpPeer
{
    SOCKET s = INVALID_SOCKET;
    bool up = false;
    std::vector<u8> rx, tx;
};

struct MpNet
{
    int mode = 0;               // 0 off, 1 host, 2 join
    char joinIP[64] = "127.0.0.1";
    SOCKET listener = INVALID_SOCKET;
    MpPeer peers[3];            // host: up to 3 clients (slot i = role 2+i);
                                // join: peers[0] = the host link
    bool connecting = false;    // join: non-blocking connect in flight
    bool freshPeer = false;     // a link just came up: pump must resend
                                // on-change channels (party/pkt) — their
                                // caches predate this peer, so it would
                                // otherwise NEVER receive our party
    u32 retryAt = 0;
    int assignedRole = 0;       // join: role handed out by the host (0xFF ctl frame)
    char myName[24] = "Player";
    char rname[5][24] = {{0}};   // lobby display name by role (1..4)
    u16 rping[5] = {0};          // that role's ping-to-host, ms
    u16 myPingMs = 0;            // our own measured ping to the host
    u32 pingSentAt = 0;          // GetTickCount at last ping send
    u32 lastPing = 0;
    u32 lastName = 0;

    void setName(const char* nm)
    {
        if (nm && nm[0]) { strncpy(myName, nm, 23); myName[23] = 0; }
    }
    void sendName(int myRole)
    {
        u8 buf[29]; int nl = (int)strlen(myName); if (nl > 23) nl = 23;
        buf[0] = 0xFE; buf[1] = (u8)myRole;
        buf[2] = (u8)(myPingMs & 0xFF); buf[3] = (u8)(myPingMs >> 8);
        buf[4] = (u8)nl; memcpy(buf + 5, myName, nl);
        sendAll(buf, 5 + nl);
        if (myRole >= 1 && myRole <= 4) { memcpy(rname[myRole], myName, nl); rname[myRole][nl] = 0; rping[myRole] = myPingMs; }
    }
    void sendPing(int myRole)   // clients ping the host
    {
        if (mode != 2 || !peers[0].up) return;
        pingSentAt = GetTickCount();
        u8 buf[6] = { 0xFD, (u8)myRole,
            (u8)(pingSentAt & 0xFF), (u8)((pingSentAt >> 8) & 0xFF),
            (u8)((pingSentAt >> 16) & 0xFF), (u8)((pingSentAt >> 24) & 0xFF) };
        enqueue(0, buf, 6);
    }

    int myRole() const { return (mode == 1) ? 1 : (assignedRole ? assignedRole : 2); }
    bool anyUp() const { for (int i = 0; i < 3; i++) if (peers[i].up) return true; return false; }

    static void setNonBlock(SOCKET s)
    {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        BOOL nd = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
    }

    // ---- LAN discovery beacon (UDP :7821, shared cross-emulator format) ----
    SOCKET beaconTx = INVALID_SOCKET;
    SOCKET beaconRx = INVALID_SOCKET;
    u32 lastBeacon = 0;

    void startBeaconTx()
    {
        beaconTx = socket(AF_INET, SOCK_DGRAM, 0);
        if (beaconTx != INVALID_SOCKET) { BOOL b = TRUE; setsockopt(beaconTx, SOL_SOCKET, SO_BROADCAST, (const char*)&b, sizeof(b)); }
    }
    void beaconBroadcast(u8 players)
    {
        if (beaconTx == INVALID_SOCKET) return;
        u8 buf[32]; memset(buf, 0, sizeof(buf));
        memcpy(buf, "PLATMP", 6); buf[6] = 1; buf[7] = players;
        // advertise the host's chosen lobby name (Host dialog), not the PC name
        int nl = (int)strlen(myName);
        if (nl == 0) { memcpy(buf + 8, "Player", 6); }
        else memcpy(buf + 8, myName, (nl < 24) ? nl : 23);
        sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(7821); a.sin_addr.s_addr = INADDR_BROADCAST;
        sendto(beaconTx, (const char*)buf, 32, 0, (sockaddr*)&a, sizeof(a));
    }
    void startBeaconRx()
    {
        if (beaconRx != INVALID_SOCKET) return;
        beaconRx = socket(AF_INET, SOCK_DGRAM, 0);
        if (beaconRx == INVALID_SOCKET) return;
        BOOL yes = TRUE; setsockopt(beaconRx, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
        sockaddr_in a; memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET; a.sin_port = htons(7821); a.sin_addr.s_addr = INADDR_ANY;
        if (bind(beaconRx, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(beaconRx); beaconRx = INVALID_SOCKET; return; }
        u_long nb = 1; ioctlsocket(beaconRx, FIONBIO, &nb);
    }

    void startHost()
    {
        mpEnsureFirewall();
        mode = 1;
        start();
        startBeaconTx();
    }
    void joinTo(const char* ip)
    {
        mode = 2;
        if (ip && ip[0]) { strncpy(joinIP, ip, sizeof(joinIP)-1); joinIP[sizeof(joinIP)-1] = 0; }
        connecting = false; retryAt = 0;
        for (int i = 0; i < 3; i++) dropPeer(i);
    }

    void start()
    {
        if (mode == 1)
        {
            listener = socket(AF_INET, SOCK_STREAM, 0);
            if (listener == INVALID_SOCKET) return;
            BOOL yes = TRUE;
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
            sockaddr_in a; memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(MP_PORT);
            if (bind(listener, (sockaddr*)&a, sizeof(a)) != 0 || listen(listener, 3) != 0)
            {
                closesocket(listener); listener = INVALID_SOCKET; return;
            }
            setNonBlock(listener);
            printf("[BR] hosting on :%d\n", MP_PORT);
        }
    }

    void dropPeer(int i)
    {
        MpPeer& p = peers[i];
        if (p.s != INVALID_SOCKET) closesocket(p.s);
        p.s = INVALID_SOCKET;
        p.up = false;
        p.rx.clear();
        p.tx.clear();
        if (mode == 2) connecting = false;
    }

    void tick(u32 frame)
    {
        if (mode == 0) return;

        if (mode == 1 && listener != INVALID_SOCKET)
        {
            // accept into any free slot; slot i is role 2+i (stable across
            // reconnects, so a rejoining player gets its old role back)
            for (int i = 0; i < 3; i++)
            {
                if (peers[i].up) continue;
                SOCKET s = accept(listener, NULL, NULL);
                if (s == INVALID_SOCKET) break;
                setNonBlock(s);
                peers[i].s = s; peers[i].up = true; freshPeer = true;
                u8 ctl[4] = { 2, 0, 0xFF, (u8)(2 + i) };   // [len=2][0xFF][role]
                peers[i].tx.insert(peers[i].tx.end(), ctl, ctl + 4);
                printf("[BR] peer accepted -> role %d\n", 2 + i);
            }
        }
        else if (mode == 2 && !peers[0].up)
        {
            MpPeer& h = peers[0];
            if (connecting)
            {
                fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex);
                FD_SET(h.s, &wr); FD_SET(h.s, &ex);
                timeval tv = { 0, 0 };
                int r = select(0, NULL, &wr, &ex, &tv);
                if (r > 0 && FD_ISSET(h.s, &wr))
                {
                    h.up = true; connecting = false; freshPeer = true;
                    printf("[BR] connected to %s\n", joinIP);
                }
                else if (r > 0 && FD_ISSET(h.s, &ex))
                {
                    dropPeer(0);
                    retryAt = frame + 120;
                }
            }
            else if (frame >= retryAt)
            {
                h.s = socket(AF_INET, SOCK_STREAM, 0);
                if (h.s == INVALID_SOCKET) { retryAt = frame + 120; return; }
                setNonBlock(h.s);
                sockaddr_in a; memset(&a, 0, sizeof(a));
                a.sin_family = AF_INET; a.sin_port = htons(MP_PORT);
                inet_pton(AF_INET, joinIP, &a.sin_addr);
                int r = connect(h.s, (sockaddr*)&a, sizeof(a));
                if (r == 0) { h.up = true; printf("[BR] connected to %s\n", joinIP); }
                else if (WSAGetLastError() == WSAEWOULDBLOCK) connecting = true;
                else { dropPeer(0); retryAt = frame + 120; }
            }
        }

        for (int i = 0; i < 3; i++) { flush(i); pumpRecv(i); }
    }

    void enqueue(int i, const u8* p, u32 n)
    {
        MpPeer& pr = peers[i];
        if (!pr.up || n == 0 || n > MP_MAX_FRAME) return;
        if (pr.tx.size() > 512 * 1024) return;
        u8 hdr[2] = { (u8)(n & 0xFF), (u8)(n >> 8) };
        pr.tx.insert(pr.tx.end(), hdr, hdr + 2);
        pr.tx.insert(pr.tx.end(), p, p + n);
        flush(i);
    }

    void sendAll(const u8* p, u32 n)
    {
        for (int i = 0; i < 3; i++) enqueue(i, p, n);
    }

    void flush(int i)
    {
        MpPeer& p = peers[i];
        if (!p.up || p.tx.empty()) return;
        int r = ::send(p.s, (const char*)p.tx.data(), (int)p.tx.size(), 0);
        if (r > 0) p.tx.erase(p.tx.begin(), p.tx.begin() + r);
        else if (r == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) dropPeer(i);
    }

    void pumpRecv(int i)
    {
        MpPeer& p = peers[i];
        if (!p.up) return;
        char tmp[16384];
        for (;;)
        {
            int r = ::recv(p.s, tmp, sizeof(tmp), 0);
            if (r > 0) { p.rx.insert(p.rx.end(), tmp, tmp + r); if (p.rx.size() > 1024*1024) { dropPeer(i); return; } }
            else if (r == 0) { dropPeer(i); printf("[BR] peer %d closed\n", i); return; }
            else
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK) { dropPeer(i); printf("[BR] peer %d error\n", i); }
                return;
            }
        }
    }

    u32 recvFrame(int i, u8* out, u32 outMax)
    {
        MpPeer& p = peers[i];
        if (p.rx.size() < 2) return 0;
        u32 n = (u32)p.rx[0] | ((u32)p.rx[1] << 8);
        if (n == 0 || n > MP_MAX_FRAME) { dropPeer(i); return 0; }
        if (p.rx.size() < 2 + n) return 0;
        u32 c = (n <= outMax) ? n : outMax;
        memcpy(out, p.rx.data() + 2, c);
        p.rx.erase(p.rx.begin(), p.rx.begin() + 2 + n);
        return c;
    }

    void shutdownAll()
    {
        for (int i = 0; i < 3; i++) dropPeer(i);
        if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
        mode = 0;
    }
};

MpNet gNet;

// ---------------------------------------------------------------------------
// Bridge pump state (verbatim melonDS BridgeSt)
// ---------------------------------------------------------------------------
struct BridgeSt
{
    bool armed = false;         // env said host/join
    u32 frame = 0;
    u32 disc = 0, ctl = 0;
    u32 exportBlk = 0, importBlk = 0, partyExp = 0, partyImp = 0;
    u32 pktExp = 0, pktImp = 0, owExp = 0, owImp = 0;
    u32 blkN = 0, partyN = 0;
    u32 blkSize = 0, partySize = 0, pktSize = 0;
    u8 beat = 0;
    std::vector<u8> lastParty, lastPkt;
    u32 dbgTx = 0, dbgRx = 0, dbgPktTx = 0, dbgPktRx = 0;

    /* Freshness-tracked peer roles, TWO tiers:
     *  - roleSeenAt: LOBBY presence — stamped by name frames (0xFE) too, so
     *    the roster shows players the moment they connect. Drives the lobby
     *    UI and the discovery beacon only.
     *  - gameSeenAt: IN-GAME presence — stamped ONLY when a game-data bundle
     *    (tag 1/2/3) from role r arrives, i.e. that player actually activated
     *    Wireless Play. Drives the ROM-visible peerMask/status; without the
     *    split, a player idling in the lobby made the game flash "wireless
     *    connected" the instant the local player activated. */
    u32 roleSeenAt[5] = { 0, 0, 0, 0, 0 };
    u32 gameSeenAt[5] = { 0, 0, 0, 0, 0 };

    u8 MaskOf(const u32* seen, int myRole) const
    {
        u8 m = 0;
        for (int r = 1; r <= 4; r++)
            if (r != myRole && seen[r] != 0 && frame - seen[r] <= 180)
                m |= (u8)(1u << (r - 1));
        return m;
    }
    u8 FreshPeerMask(int myRole) const { return MaskOf(roleSeenAt, myRole); }
    u8 GamePeerMask(int myRole)  const { return MaskOf(gameSeenAt, myRole); }
};
BridgeSt gBr;

// ---------------------------------------------------------------------------
// Autopilot state (port of the melonDS ap* namespace)
// ---------------------------------------------------------------------------
int apMode = -1;                // -1 off, 0 host, 1 join
int apHold = 0;
int patMode = 0;                // 0 walk, 1 run, 2 circle, 3 waggle, 4 ugclient, 5 ughost
u32 apFrame = 0;
u32 apConnFrame = 0;
int apInField = 0;
u32 apFieldFC = 0;
u32 apTouchFrames = 0;          // scripted stylus press countdown (seamwalk pattern)
FILE* apCsv = NULL;

// --- input record / replay (patMode 10 = record, 11 = replay) -------------
// Frame-accurate button capture.  Record logs the user's real pad each frame
// on-change; replay forces the same bits back.  Both anchor at field entry
// (apInField) so boot/connect timing differences wash out — so the replay
// instance must start from the SAME save/state as the recording.  Mask bit
// layout matches the press mask below: A0 B1 sel2 start3 R4 L5 U6 D7 X10 Y11.
struct ApRepEntry { u32 f; u32 mask; };
static const int AP_REP_MAX = 65536;
ApRepEntry apRepTab[AP_REP_MAX];
int   apRepCount = 0, apRepIdx = 0;
u32   apRepMask = 0, apAnchorFrame = 0, apRecLastMask = 0xFFFFFFFFu;
FILE* apRecFile = NULL;
int   apRecStarted = 0;

} // namespace

// ---------------------------------------------------------------------------

// ===========================================================================
// Win32 LAN lobby: Multiplayer menu -> Host / Join dialogs (name entry +
// auto-find list + direct IP) -> a modeless lobby window showing the player
// roster.  Drives the same TCP bridge as env, so it interoperates with the
// melonDS and BizHawk forks.  main.cpp forwards 3 messages.
// ===========================================================================
namespace {
#ifdef _WIN32
enum { MP_ID_HOST = 0xE100, MP_ID_JOIN, MP_ID_STOP };
HMENU gMpMenu = NULL;
struct FoundHost { char ip[32]; char name[28]; u32 seen; };
FoundHost gFound[8]; int gFoundN = 0;
HWND gLobby = NULL;

void MpArm() { gBr.armed = true; printf("[BR] armed via menu: mode=%d\n", gNet.mode); fflush(stdout); }

void MpBrowsePoll()
{
    gNet.startBeaconRx();
    if (gNet.beaconRx == INVALID_SOCKET) return;
    for (;;) {
        u8 buf[64]; sockaddr_in from; int fl = sizeof(from);
        int r = recvfrom(gNet.beaconRx, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (r < 8) break;
        if (memcmp(buf, "PLATMP", 6) != 0) continue;
        char ip[32]; strcpy(ip, inet_ntoa(from.sin_addr));
        char nm[28]; memset(nm, 0, sizeof(nm)); memcpy(nm, buf + 8, (r - 8 < 24) ? (r - 8) : 24);
        int idx = -1;
        for (int i = 0; i < gFoundN; i++) if (!strcmp(gFound[i].ip, ip)) { idx = i; break; }
        if (idx < 0 && gFoundN < 8) idx = gFoundN++;
        if (idx >= 0) { strncpy(gFound[idx].ip, ip, 31); strncpy(gFound[idx].name, nm, 27); gFound[idx].seen = 0; }
    }
    for (int i = 0; i < gFoundN; ) { if (++gFound[i].seen > 12) { gFound[i] = gFound[--gFoundN]; } else i++; }
}

// --- in-memory DLGTEMPLATE builder ---
void AddItem(BYTE*& p, DWORD style, short x, short y, short cx, short cy, WORD id, WORD cls, const wchar_t* text)
{
    p = (BYTE*)(((ULONG_PTR)p + 3) & ~(ULONG_PTR)3);
    DLGITEMTEMPLATE* it = (DLGITEMTEMPLATE*)p; p += sizeof(DLGITEMTEMPLATE);
    it->style = style | WS_CHILD | WS_VISIBLE; it->dwExtendedStyle = 0;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy; it->id = id;
    *(WORD*)p = 0xFFFF; p += 2; *(WORD*)p = cls; p += 2;
    int n = 0; while (text[n]) { *(WCHAR*)p = text[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    *(WORD*)p = 0; p += 2;
}
BYTE* BeginDlg(BYTE* buf, WORD cdit, short cx, short cy, const wchar_t* cap)
{
    BYTE* p = buf;
    DLGTEMPLATE* t = (DLGTEMPLATE*)p; p += sizeof(DLGTEMPLATE);
    t->style = DS_MODALFRAME | DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT;
    t->dwExtendedStyle = 0; t->cdit = cdit; t->x = 0; t->y = 0; t->cx = cx; t->cy = cy;
    *(WORD*)p = 0; p += 2; *(WORD*)p = 0; p += 2;
    int n = 0; while (cap[n]) { *(WCHAR*)p = cap[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    *(WORD*)p = 8; p += 2;
    const wchar_t* fn = L"MS Shell Dlg"; n = 0; while (fn[n]) { *(WCHAR*)p = fn[n]; p += 2; n++; } *(WCHAR*)p = 0; p += 2;
    return p;
}

// --- lobby window (modeless) ---
INT_PTR CALLBACK LobbyProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_INITDIALOG: SetTimer(h, 1, 500, NULL); return TRUE;
    case WM_TIMER: {
        char st[96];
        if (gNet.mode == 1) _snprintf(st, sizeof(st), "Hosting on port 7820 - waiting for players");
        else _snprintf(st, sizeof(st), "%s %s", gNet.anyUp() ? "Connected to" : "Connecting to", gNet.joinIP);
        SetDlgItemTextA(h, 200, st);
        HWND lb = GetDlgItem(h, 201);
        SendMessageA(lb, LB_RESETCONTENT, 0, 0);
        int me = gNet.myRole(); u8 mask = gBr.FreshPeerMask(me);
        for (int r = 1; r <= 4; r++) {
            bool present = (r == me) || (mask & (1 << (r - 1)));
            if (!present) continue;
            char line[80];
            const char* nm = (r == me) ? gNet.myName : (gNet.rname[r][0] ? gNet.rname[r] : "");
            char who[32]; if (!nm[0]) _snprintf(who, sizeof(who), "Player %d", r); else { strncpy(who, nm, 31); who[31]=0; }
            if (r == me && gNet.mode == 2)
                              _snprintf(line, sizeof(line), "%s (you)  -  %u ms", who, gNet.myPingMs);
            else if (r == me) _snprintf(line, sizeof(line), "%s (you)", who);
            else if (r == 1)  _snprintf(line, sizeof(line), "%s (host)", who);
            else              _snprintf(line, sizeof(line), "%s  -  %u ms", who, gNet.rping[r]);
            SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)line);
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDCANCEL || LOWORD(w) == IDOK) {
            KillTimer(h, 1);
            gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false;
            DestroyWindow(h); gLobby = NULL; return TRUE;
        }
        break;
    case WM_CLOSE:
        KillTimer(h, 1); gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false;
        DestroyWindow(h); gLobby = NULL; return TRUE;
    }
    return FALSE;
}
void OpenLobby(HWND parent)
{
    if (gLobby) { SetForegroundWindow(gLobby); return; }
    static BYTE buf[1024]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 4, 190, 150, L"Wireless Lobby");
    // the lobby stays open for the whole session — let players minimize it
    ((DLGTEMPLATE*)buf)->style |= WS_MINIMIZEBOX;
    AddItem(p, SS_LEFT, 8, 8, 174, 10, 200, 0x0082, L"Starting...");
    AddItem(p, WS_BORDER | LBS_NOINTEGRALHEIGHT, 8, 22, 174, 100, 201, 0x0083, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 70, 128, 50, 14, IDCANCEL, 0x0080, L"Leave");
    AddItem(p, SS_LEFT, 8, 130, 60, 10, 202, 0x0082, L"Use Wireless Play in-game.");
    gLobby = CreateDialogIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, LobbyProc, 0);
    ShowWindow(gLobby, SW_SHOW);
}

// --- host dialog (name entry) ---
static char gDlgName[24];
INT_PTR CALLBACK HostProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_INITDIALOG) { SetDlgItemTextA(h, 100, gNet.myName); SetFocus(GetDlgItem(h, 100)); return FALSE; }
    if (m == WM_COMMAND) {
        if (LOWORD(w) == IDOK) { GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName)); EndDialog(h, 1); return TRUE; }
        if (LOWORD(w) == IDCANCEL) { EndDialog(h, 0); return TRUE; }
    }
    return FALSE;
}
// --- join dialog (name + list + direct IP) ---
INT_PTR CALLBACK JoinProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    switch (m) {
    case WM_INITDIALOG:
        SetDlgItemTextA(h, 100, gNet.myName);
        SetDlgItemTextA(h, 102, gNet.joinIP);
        SetTimer(h, 2, 700, NULL);
        return FALSE;
    case WM_TIMER: {
        MpBrowsePoll();
        HWND lb = GetDlgItem(h, 101);
        int sel = (int)SendMessageA(lb, LB_GETCURSEL, 0, 0);
        SendMessageA(lb, LB_RESETCONTENT, 0, 0);
        for (int i = 0; i < gFoundN; i++) {
            char line[80]; _snprintf(line, sizeof(line), "%s  (%s)", gFound[i].name, gFound[i].ip);
            SendMessageA(lb, LB_ADDSTRING, 0, (LPARAM)line);
        }
        if (sel >= 0 && sel < gFoundN) SendMessageA(lb, LB_SETCURSEL, sel, 0);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDOK) {
            GetDlgItemTextA(h, 100, gDlgName, sizeof(gDlgName));
            char ip[64] = {0};
            int sel = (int)SendMessageA(GetDlgItem(h, 101), LB_GETCURSEL, 0, 0);
            if (sel >= 0 && sel < gFoundN) strncpy(ip, gFound[sel].ip, 63);
            else GetDlgItemTextA(h, 102, ip, sizeof(ip));
            if (!ip[0]) { MessageBoxA(h, "Pick a game or enter an IP.", "Join", MB_OK); return TRUE; }
            strncpy(gDlgName + 24, "", 0);  // noop keep
            lstrcpynA((LPSTR)gNet.joinIP, ip, sizeof(gNet.joinIP));
            KillTimer(h, 2); EndDialog(h, 1); return TRUE;
        }
        if (LOWORD(w) == IDCANCEL) { KillTimer(h, 2); EndDialog(h, 0); return TRUE; }
        break;
    }
    return FALSE;
}
bool ShowHostDialog(HWND parent)
{
    static BYTE buf[1024]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 4, 180, 62, L"Host LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 160, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 8, 22, 164, 12, 100, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 60, 42, 56, 14, IDOK, 0x0080, L"Host Game");
    AddItem(p, WS_TABSTOP | BS_PUSHBUTTON, 122, 42, 50, 14, IDCANCEL, 0x0080, L"Cancel");
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, HostProc, 0) == 1;
}
bool ShowJoinDialog(HWND parent)
{
    static BYTE buf[1536]; memset(buf, 0, sizeof(buf));
    BYTE* p = BeginDlg(buf, 7, 200, 150, L"Join LAN Game");
    AddItem(p, SS_LEFT, 8, 8, 80, 10, (WORD)-1, 0x0082, L"Your name:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 88, 6, 104, 12, 100, 0x0081, L"");
    AddItem(p, SS_LEFT, 8, 24, 184, 10, (WORD)-1, 0x0082, L"LAN games found:");
    AddItem(p, WS_BORDER | WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 8, 36, 184, 70, 101, 0x0083, L"");
    AddItem(p, SS_LEFT, 8, 110, 60, 10, (WORD)-1, 0x0082, L"or IP address:");
    AddItem(p, WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 70, 108, 122, 12, 102, 0x0081, L"");
    AddItem(p, WS_TABSTOP | BS_DEFPUSHBUTTON, 74, 130, 50, 14, IDOK, 0x0080, L"Join");
    // Cancel shares the row via IDCANCEL implicit (Esc) — add explicit:
    return DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPCDLGTEMPLATEA)buf, parent, JoinProc, 0) == 1;
}
} // namespace

void MpBridge_InstallMenu(HWND mainWnd)
{
    HMENU bar = GetMenu(mainWnd);
    if (!bar) return;
    gMpMenu = CreatePopupMenu();
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_HOST, "&Host LAN Game...");
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_JOIN, "&Join LAN Game...");
    AppendMenuA(gMpMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(gMpMenu, MF_STRING, MP_ID_STOP, "Dis&connect");
    InsertMenuA(bar, (UINT)-1, MF_BYPOSITION | MF_POPUP, (UINT_PTR)gMpMenu, "&Multiplayer");
    DrawMenuBar(mainWnd);
}

void MpBridge_OnInitPopup(HMENU menu)
{
    if (menu != gMpMenu) return;
    EnableMenuItem(gMpMenu, MP_ID_HOST, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_JOIN, MF_BYCOMMAND | (gNet.mode ? MF_GRAYED : MF_ENABLED));
    EnableMenuItem(gMpMenu, MP_ID_STOP, MF_BYCOMMAND | (gNet.mode ? MF_ENABLED : MF_GRAYED));
}

bool MpBridge_HandleCommand(unsigned int id)
{
    HWND w = GetActiveWindow();
    if (id == MP_ID_HOST) {
        if (ShowHostDialog(w)) { gNet.setName(gDlgName); gNet.startHost(); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_JOIN) {
        gFoundN = 0;
        if (ShowJoinDialog(w) && gNet.joinIP[0]) { gNet.setName(gDlgName); gNet.joinTo(gNet.joinIP); MpArm(); OpenLobby(w); }
        return true;
    }
    if (id == MP_ID_STOP) {
        if (gLobby) { DestroyWindow(gLobby); gLobby = NULL; }
        gNet.shutdownAll(); gNet.mode = 0; gBr.armed = false; return true;
    }
    return false;
}
#else
// The GTK frontend wires the bridge's environment-controlled startup first.
// Native Host/Join/Lobby controls are implemented separately in gtk/main.cpp.
} // namespace
void MpBridge_InstallMenu(HWND) {}
void MpBridge_OnInitPopup(HMENU) {}
bool MpBridge_HandleCommand(unsigned int) { return false; }
#endif

void MpBridge_InitFromEnv()
{
    const char* e = getenv("MELONDS_AP");     // name kept for harness compat
    if (!e) return;
    if (!strcmp(e, "host")) { apMode = 0; gNet.mode = 1; }
    else if (!strcmp(e, "join")) { apMode = 1; gNet.mode = 2; }
    else return;

    const char* ip = getenv("MELONDS_AP_IP");
    if (ip) { strncpy(gNet.joinIP, ip, sizeof(gNet.joinIP) - 1); gNet.joinIP[sizeof(gNet.joinIP)-1] = 0; }
    apHold = getenv("MELONDS_AP_HOLD") ? 1 : 0;
    const char* pat = getenv("MELONDS_AP_PATTERN");
    patMode = (!pat) ? 0 : (!strcmp(pat, "run")) ? 1
            : (!strcmp(pat, "circle")) ? 2
            : (!strcmp(pat, "waggle")) ? 3
            : (!strcmp(pat, "ugclient")) ? 4
            : (!strcmp(pat, "ughost")) ? 5
            : (!strcmp(pat, "startercrash")) ? 6
            : (!strcmp(pat, "seamwalk")) ? 7
            : (!strcmp(pat, "challenge")) ? 8
            : (!strcmp(pat, "live")) ? 9
            : (!strcmp(pat, "record")) ? 10
            : (!strcmp(pat, "replay")) ? 11 : 0;

    gBr.armed = true;
    if (gNet.mode == 1) gNet.startHost(); else gNet.start();
    printf("[BR] armed: %s pattern=%d\n", (apMode == 0) ? "host" : "join", patMode);
    fflush(stdout);
}

void MpBridge_Shutdown()
{
    gNet.shutdownAll();
    if (apCsv) { fclose(apCsv); apCsv = NULL; }
    if (apRecFile) { fclose(apRecFile); apRecFile = NULL; }
}

bool MpBridge_StartHost(const char* name)
{
    if (gNet.mode) return false;
    gNet.setName(name);
    gNet.startHost();
    if (gNet.listener == INVALID_SOCKET) { gNet.mode = 0; return false; }
    gBr.armed = true;
    return true;
}

bool MpBridge_Join(const char* name, const char* ip)
{
    if (gNet.mode || !ip || !ip[0]) return false;
    in_addr address;
    if (inet_pton(AF_INET, ip, &address) != 1) return false;
    gNet.setName(name);
    gNet.joinTo(ip);
    gBr.armed = true;
    return true;
}

void MpBridge_Stop()
{
    gNet.shutdownAll();
    gNet.mode = 0;
    gBr.armed = false;
}

bool MpBridge_IsActive()
{
    return gNet.mode != 0;
}

void MpBridge_GetLobbyText(char* out, unsigned int outSize)
{
    if (!out || outSize == 0) return;
    out[0] = 0;
    if (!gNet.mode) { snprintf(out, outSize, "No active Project PM session."); return; }

    unsigned int used = 0;
    auto append = [&](const char* fmt, const char* name, unsigned int ping) {
        if (used >= outSize - 1) return;
        int n = snprintf(out + used, outSize - used, fmt, name, ping);
        if (n > 0) used += ((unsigned int)n < outSize - used) ? (unsigned int)n : outSize - used - 1;
    };

    if (gNet.mode == 1)
        append("Hosting on TCP port 7820\n\n", "", 0);
    else if (gNet.anyUp())
        append("Connected to %s\n\n", gNet.joinIP, 0);
    else
        append("Connecting to %s...\n\n", gNet.joinIP, 0);

    const int mine = gNet.myRole();
    const u8 peers = gBr.FreshPeerMask(mine);
    append("%s (you)\n", gNet.myName, 0);
    for (int role = 1; role <= 4; role++)
    {
        if (role == mine || !(peers & (1u << (role - 1)))) continue;
        const char* name = gNet.rname[role][0] ? gNet.rname[role] : "Player";
        if (role == 1) append("%s (host)\n", name, 0);
        else append("%s - %u ms\n", name, gNet.rping[role]);
    }
}

// ---------------------------------------------------------------------------
// Per-frame pump — melonDS BridgePump ported.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Alarm-corruption tripwire.  The seam freeze was a wild thumb-jump in the
// IRQ handler: an ARMED OSAlarm's handler pointer got overwritten (with what
// looked like 15-bit colour data) and the alarm then fired.  The ROM exports
// &OSi_AlarmQueue at ctl+16; every frame we walk the queue, learn the armed
// alarm structs (they are stable allocations), and watch queue + structs.
// The core's write paths call MpWatch_OnWrite for EVERY CPU/DMA write while
// armed (see lua-engine.h); writes from outside the SDK library region get
// logged with the writing PC — the scribbler, caught red-handed.
// ---------------------------------------------------------------------------
bool gMpWatchArmed = false;
struct MpWatchRange { u32 lo, hi; };
static MpWatchRange sWatchRanges[20];
static int  sWatchCount = 0;
static u32  sWatchQueueAddr = 0;
static u32  sWatchNodes[16];
static int  sWatchNodeCount = 0;
static u32  sNodeSnapHandler[16];
static u32  sWatchHits = 0;
static FILE* sWatchLogF = NULL;

static void MpWatchLog(const char* fmt, ...)
{
    if (!sWatchLogF) sWatchLogF = fopen("desmume_alarmwatch.txt", "a");
    if (!sWatchLogF) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(sWatchLogF, fmt, ap);
    va_end(ap);
    fflush(sWatchLogF);
}

static int sWatchRole = 0;
static int sTableRange = -1;   // extra range from mp_table_watch.txt: log ALL writers

void MpWatch_OnWrite(unsigned int address, int size, unsigned int value)
{
    for (int i = 0; i < sWatchCount; i++)
    {
        if (address >= sWatchRanges[i].lo && address < sWatchRanges[i].hi)
        {
            u32 pc9 = NDS_ARM9.instruct_adr;
            // The SDK libraries legitimately maintain their own statics
            // (queue ops, thread saves, card state) — only FOREIGN writers
            // matter.  The table watch is the exception: there we want EVERY
            // writer's PC, engine code included.
            if (i != sTableRange && pc9 >= 0x020CF000 && pc9 < 0x020DF000) return;
            // Dedupe on (PC, 16-byte bucket): game callbacks running on the
            // card/sound threads write their stack frames in-band constantly;
            // one line per distinct writer+target keeps the log readable
            // without losing the one write that matters.
            {
                static u32 sSeenPC[192], sSeenAddr[192];
                static int sSeenN = 0;
                u32 bucket = address & ~0xFu;
                for (int k = 0; k < sSeenN; k++)
                    if (sSeenPC[k] == pc9 && sSeenAddr[k] == bucket) return;
                if (sSeenN < 192) { sSeenPC[sSeenN] = pc9; sSeenAddr[sSeenN] = bucket; sSeenN++; }
            }
            if (sWatchHits++ > 1500) return;   // absolute cap
            MpWatchLog("WRITE role=%d f=%u addr=%08X val=%08X size=%d PC9=%08X LR9=%08X CPSR9=%08X PC7=%08X\n",
                sWatchRole, gBr.frame, address, value, size,
                pc9, NDS_ARM9.R[14], NDS_ARM9.CPSR.val, NDS_ARM7.instruct_adr);
            return;
        }
    }
}

void MpBridge_Pump()
{
    if (!gBr.armed) return;
    gBr.frame++;

    gNet.tick(gBr.frame);

    // A peer link just came up: drop the on-change send caches so the next
    // pump resends party/pkt to everyone.  Without this a peer connecting
    // AFTER our first send NEVER received our party — the receiving side's
    // battle/trade launch waits on partner party bytes forever ("the
    // accepter never gets the message").
    if (gNet.freshPeer)
    {
        gNet.freshPeer = false;
        gBr.lastParty.clear();
        gBr.lastPkt.clear();
    }

    // ROM discovery: scan periodically until found. Must NOT gate the
    // transport exchange below — the lobby connects at the title screen,
    // long before the game runs Multiplayer_Update()/InitDiscovery() in the
    // overworld and publishes the discovery block.
    if (!gBr.disc && (gBr.frame % 60) == 0)
    {
        for (u32 off = 0; off < 0x400000 - 16; off += 4)
        {
            if (T1ReadLong(MMU.MAIN_MEM, off) == 0xCAFE1234
                && T1ReadLong(MMU.MAIN_MEM, off + 4) == 0x5678CAFE)
            {
                gBr.disc = 0x02000000 + off;
                printf("[AP] discovery at %08X\n", gBr.disc);
                gBr.exportBlk = apRd32(gBr.disc + 2*4);
                gBr.importBlk = apRd32(gBr.disc + 3*4);
                gBr.partyExp  = apRd32(gBr.disc + 4*4);
                gBr.partyImp  = apRd32(gBr.disc + 5*4);
                gBr.pktExp    = apRd32(gBr.disc + 12*4);
                gBr.pktImp    = apRd32(gBr.disc + 13*4);
                gBr.owExp     = apRd32(gBr.disc + 14*4);
                gBr.owImp     = apRd32(gBr.disc + 15*4);
                gBr.blkSize   = apRd32(gBr.disc + 20*4) & 0xFFFF;
                gBr.blkN      = apRd32(gBr.disc + 25*4);
                gBr.partyN    = apRd32(gBr.disc + 26*4);
                gBr.ctl       = apRd32(gBr.disc + 31*4);
                break;
            }
        }
    }
    if (gBr.disc && !gBr.ctl)
        gBr.ctl = apRd32(gBr.disc + 31*4);   // [31] published after the sig
    bool romUp = (gBr.ctl != 0 && apRd32(gBr.ctl) == 0x42524731);
    if (romUp)
    {
        gBr.partySize = apRd16(gBr.ctl + 10);
        gBr.pktSize   = apRd16(gBr.ctl + 12);
        apWr8(gBr.ctl + 6, ++gBr.beat);   // fork heartbeat
    }

    if (gNet.mode == 1 && (gBr.frame - gNet.lastBeacon) >= 60) {
        gNet.lastBeacon = gBr.frame;
        gNet.beaconBroadcast((u8)(gBr.FreshPeerMask(gNet.myRole()) ? 2 : 1));
    }
    if (gNet.anyUp() && (gNet.mode == 1 || gNet.assignedRole)
        && (gBr.frame - gNet.lastName) >= 30) {
        gNet.lastName = gBr.frame;
        gNet.sendName(gNet.myRole());
    }
    if (gNet.mode == 2 && (gBr.frame - gNet.lastPing) >= 30) {
        gNet.lastPing = gBr.frame;
        gNet.sendPing(gNet.myRole());
    }

    int myRole = gNet.myRole();
    u8 wanted = romUp ? apRd8(gBr.ctl + 4) : 0;
    bool inGame = (romUp && wanted && gBr.blkSize != 0 && gBr.blkSize <= 512
        && gBr.partySize != 0 && gBr.partySize <= 2048
        && gBr.pktSize != 0 && gBr.pktSize <= 2048);

    // NOTE: no early-return when the ROM side isn't up yet. The lobby connects
    // and exchanges name/ping frames at the title screen, so the recv loop
    // below must run every armed frame or joined players never appear in the
    // lobby roster. Everything touching ROM RAM is gated on romUp/inGame.
    if (romUp)
    {
        apWr8(gBr.ctl + 8, (u8)myRole);
        if (!inGame)
        {
            apWr8(gBr.ctl + 7, 0);
            apWr8(gBr.ctl + 9, 0);
            gBr.lastParty.clear();
            gBr.lastPkt.clear();
        }
    }

    if (inGame && gNet.anyUp())
    {
        static std::vector<u8> buf;
        buf.resize(4 + 2048 + 48);

        // bundle: [1][role][blkSize u16][block][ow 48] — every frame
        buf[0] = 1; buf[1] = (u8)myRole;
        buf[2] = (u8)(gBr.blkSize & 0xFF); buf[3] = (u8)(gBr.blkSize >> 8);
        memcpy(buf.data() + 4, apPtr(gBr.exportBlk), gBr.blkSize);
        memcpy(buf.data() + 4 + gBr.blkSize, apPtr(gBr.owExp), 48);
        gNet.sendAll(buf.data(), 4 + gBr.blkSize + 48); gBr.dbgTx++;

        // party: on content change
        if (gBr.lastParty.size() != gBr.partySize
            || memcmp(gBr.lastParty.data(), apPtr(gBr.partyExp), gBr.partySize) != 0)
        {
            gBr.lastParty.assign(apPtr(gBr.partyExp), apPtr(gBr.partyExp) + gBr.partySize);
            buf[0] = 2; buf[1] = (u8)myRole;
            buf[2] = (u8)(gBr.partySize & 0xFF); buf[3] = (u8)(gBr.partySize >> 8);
            memcpy(buf.data() + 4, gBr.lastParty.data(), gBr.partySize);
            gNet.sendAll(buf.data(), 4 + gBr.partySize);
        }

        // pkt channel: on content change
        if (gBr.lastPkt.size() != gBr.pktSize
            || memcmp(gBr.lastPkt.data(), apPtr(gBr.pktExp), gBr.pktSize) != 0)
        {
            gBr.lastPkt.assign(apPtr(gBr.pktExp), apPtr(gBr.pktExp) + gBr.pktSize);
            buf[0] = 3; buf[1] = (u8)myRole;
            buf[2] = (u8)(gBr.pktSize & 0xFF); buf[3] = (u8)(gBr.pktSize >> 8);
            memcpy(buf.data() + 4, gBr.lastPkt.data(), gBr.pktSize);
            gNet.sendAll(buf.data(), 4 + gBr.pktSize); gBr.dbgPktTx++;
        }
    }

    // receive: apply peers' mailboxes (per peer link; host relays)
    {
        u8 rx[MP_MAX_FRAME];
        u32 n;
        for (int pi = 0; pi < 3; pi++)
        while ((n = gNet.recvFrame(pi, rx, sizeof(rx))) > 0)
        {
            gBr.dbgRx++;
            if (n == 2 && rx[0] == 0xFF)
            {
                // control: host-assigned role (joiner side)
                gNet.assignedRole = rx[1];
                gNet.sendName(gNet.myRole());   // announce our name on join
                continue;
            }
            if (n == 6 && rx[0] == 0xFD) {
                // client ping -> echo back as pong on the same peer link
                u8 pong[6]; memcpy(pong, rx, 6); pong[0] = 0xFC;
                gNet.enqueue(pi, pong, 6);
                continue;
            }
            if (n == 6 && rx[0] == 0xFC) {
                // pong for our ping: RTT = now - stamped tick
                u32 tick = rx[2] | (rx[3] << 8) | (rx[4] << 16) | ((u32)rx[5] << 24);
                u32 rtt = GetTickCount() - tick;
                gNet.myPingMs = (rtt > 9999) ? 9999 : (u16)rtt;
                continue;
            }
            if (n >= 5 && rx[0] == 0xFE) {
                // lobby name announce: [0xFE][role][ping16][len][name]
                int r2 = rx[1]; u16 png = (u16)(rx[2] | (rx[3] << 8)); int nl = rx[4];
                if (r2 >= 1 && r2 <= 4 && nl <= 23 && (u32)n >= (u32)(5 + nl)) {
                    memcpy(gNet.rname[r2], rx + 5, nl); gNet.rname[r2][nl] = 0; gNet.rping[r2] = png;
                    gBr.roleSeenAt[r2] = gBr.frame;
                    if (myRole == 1) for (int pj = 0; pj < 3; pj++) if (pj != pi) gNet.enqueue(pj, rx, n);
                }
                continue;
            }
            if (n < 4) continue;
            int tag = rx[0], r = rx[1];
            u32 sz = (u32)(rx[2] | (rx[3] << 8));
            if (r < 1 || r > 4 || r == myRole) continue;
            if (n < 4 + sz) continue;

            // Host relay: clients only reach the host — forward every client
            // bundle to the other clients so they see EACH OTHER (the origin
            // ignores its own echo via the r == myRole check).
            if (myRole == 1)
                for (int pj = 0; pj < 3; pj++)
                    if (pj != pi) gNet.enqueue(pj, rx, n);

            gBr.roleSeenAt[r] = gBr.frame;
            if (tag >= 1 && tag <= 3)
            {
                // Peer NEWLY game-active (just activated Wireless Play, or
                // reconnected): resend our on-change channels — anything we
                // sent before this moment predates their readiness.
                bool wasFresh = gBr.gameSeenAt[r] != 0 && gBr.frame - gBr.gameSeenAt[r] <= 180;
                if (!wasFresh)
                {
                    gBr.lastParty.clear();
                    gBr.lastPkt.clear();
                }
                gBr.gameSeenAt[r] = gBr.frame;
            }

            // Game-mailbox apply whenever the ROM's discovery block is up
            // (romUp) — NOT gated on our own activation: the mailboxes are
            // inert BSS until the ROM activates, and dropping pre-activation
            // frames LOST the peer's one-shot on-change party send when they
            // activated before us (the accepter never activated: its battle/
            // trade launch waits on partner party bytes forever).
            //
            // LEGACY-CHANNEL PAIR ROUTING (3+ players): the single pairwise
            // import block / party buffer must only receive the CHOSEN pair
            // partner's data — the ROM publishes its intent in the OW export
            // (pairRole @ +0x18; 0 = unpaired, keep first-come legacy
            // behaviour).  Without this every peer's bundle overwrote the
            // legacy block (last writer wins) and battle/trade/give requests
            // "broadcast" to every player.  Per-role arrays always update.
            if (romUp && tag == 1 && sz == gBr.blkSize && n >= 4 + sz + 48)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                // STRICT 3+ ROUTING (4P same-trainer fix): with two or more
                // game-active peers, the legacy pairwise import only ever
                // receives the CHOSEN partner (r == pairRole).  The old
                // "pairRole 0 accepts everyone, last writer wins" open door
                // is 2P protocol -- but in a 4P session it let a MID-BATTLE
                // pair's per-turn block broadcasts (same trainerHash!) land
                // in a still-unpaired third player's import during their
                // entry stall, so P3 converted/synced against P1 instead of
                // waiting for P4.  Unpaired in 3+ now receives nothing and
                // simply keeps stalling for the real partner.
                // Peer count for strictness: lobby-fresh (heartbeats keep
                // roleSeenAt alive even mid-battle) AND has ever been
                // game-active.  GamePeerMask aged out mid-battle (frozen
                // exports stop game traffic), silently re-opening the door
                // exactly while P1+P2 fought -- the war-zone imports that
                // starved P3+P4's conversion (2026-07-23 4P trace).
                int gamePeers = 0;
                for (int gb = 1; gb <= 4; gb++)
                    if (gb != myRole && gBr.roleSeenAt[gb] != 0
                        && gBr.frame - gBr.roleSeenAt[gb] <= 300
                        && gBr.gameSeenAt[gb] != 0) gamePeers++;
                bool strict = (gamePeers >= 2);
                rx[4 + 0x12] = (u8)r;   // stamp playerRole (the old hub did this;
                                        // MpPartnerIsLead is dead without it)
                if ((pairRole == 0 && !strict) || r == (int)pairRole)
                    memcpy(apPtr(gBr.importBlk), rx + 4, sz);
                if (gBr.blkN) memcpy(apPtr(gBr.blkN + (r-1)*sz), rx + 4, sz);
                memcpy(apPtr(gBr.owImp + (r-1)*48), rx + 4 + sz, 48);
            }
            else if (romUp && tag == 2 && sz == gBr.partySize)
            {
                u8 pairRole = apRd8(gBr.owExp + 0x18);
                int gamePeers = 0;
                for (int gb = 1; gb <= 4; gb++)
                    if (gb != myRole && gBr.roleSeenAt[gb] != 0
                        && gBr.frame - gBr.roleSeenAt[gb] <= 300
                        && gBr.gameSeenAt[gb] != 0) gamePeers++;
                bool strict = (gamePeers >= 2);
                if ((pairRole == 0 && !strict) || r == (int)pairRole)
                    memcpy(apPtr(gBr.partyImp), rx + 4, sz);
                if (gBr.partyN) memcpy(apPtr(gBr.partyN + (r-1)*sz), rx + 4, sz);
            }
            else if (romUp && tag == 3 && sz == gBr.pktSize)
            {
                memcpy(apPtr(gBr.pktImp + (r-1)*sz), rx + 4, sz);
                gBr.dbgPktRx++;
            }
        }
    }

    // PAIR REBIND / GHOST PURGE.  On a pairRole change to a REAL role, replay
    // that role's latest cached block/party from the always-updated per-role
    // arrays so the pair is instantly consistent.  A change to 0 is left
    // ALONE: the ROM's pair re-validate briefly flaps pairRole to 0 when the
    // partner's conversion window closes (published trainerHash drops for a
    // tick) and re-courts mutually the next scan tick -- zeroing here killed
    // the P3+P4 conversion mid-handshake (2026-07-23 regression).  The stale
    // ex-partner hazard is handled where it actually bites: when OUR OWN
    // battle ends (export inBattle 1->0), the import's magic dies so a
    // frozen mid-battle partner block can't convert a LATER battle.
    if (romUp && gBr.owExp && gBr.importBlk)
    {
        static u8 sLastPairRole = 0xFF;
        u8 pr = apRd8(gBr.owExp + 0x18);
        if (pr != sLastPairRole)
        {
            sLastPairRole = pr;
            if (pr >= 1 && pr <= 4)
            {
                if (gBr.blkN)
                    memcpy(apPtr(gBr.importBlk), apPtr(gBr.blkN + (pr-1)*gBr.blkSize), gBr.blkSize);
                if (gBr.partyN && gBr.partyImp)
                    memcpy(apPtr(gBr.partyImp), apPtr(gBr.partyN + (pr-1)*gBr.partySize), gBr.partySize);
            }
        }
    }
    if (romUp && gBr.exportBlk && gBr.importBlk)
    {
        static u8 sLastOwnInBattle = 0;
        u8 ib = apRd8(gBr.exportBlk + 0x10);
        if (!ib && sLastOwnInBattle)
            apWr32(gBr.importBlk, 0);   // battle over: purge partner-block ghost
        sLastOwnInBattle = ib;
    }

    if (inGame)
    {
        // GAME peer mask, not the lobby one: "connected" must mean the peer
        // is actually streaming game data (activated Wireless Play), not
        // merely sitting in the lobby.
        u8 pm = gBr.GamePeerMask(myRole);
        apWr8(gBr.ctl + 7, pm ? 2 : 1);   // status
        apWr8(gBr.ctl + 9, pm);           // peerMask
    }

    if ((gBr.frame % 120) == 0)
    {
        printf("[BR] f=%u role=%d wanted=%u lobby=%u game=%u tx=%u rx=%u pktTx=%u pktRx=%u\n",
            gBr.frame, myRole, wanted, gBr.FreshPeerMask(myRole), gBr.GamePeerMask(myRole),
            gBr.dbgTx, gBr.dbgRx, gBr.dbgPktTx, gBr.dbgPktRx);
        fflush(stdout);
    }

    // ALWAYS-ON crash catcher: overworld frame counter frozen while a session
    // is wanted => the ARM9 is wedged/crashed; dump registers for the map.
    if (romUp)
    {
        static u32 ccLastFC = 0, ccChangedAt = 0;
        static int ccDumped = 0;
        u32 fcNow = apRd32(gBr.owExp + 0x0C);
        if (fcNow != ccLastFC)
        {
            ccLastFC = fcNow;
            ccChangedAt = gBr.frame;
            ccDumped = 0;
        }
        else if (wanted && gBr.frame - ccChangedAt > 180 && ccDumped < 24)
        {
            FILE* cf = fopen("desmume_hangpc_auto.txt", "a");
            if (cf)
            {
                fprintf(cf, "role=%d f=%u FCstuck=%u R15=%08X R14=%08X R13=%08X R12=%08X CPSR=%08X\n",
                    myRole, gBr.frame, fcNow,
                    NDS_ARM9.instruct_adr, NDS_ARM9.R[14], NDS_ARM9.R[13], NDS_ARM9.R[12],
                    NDS_ARM9.CPSR.val);
                fprintf(cf, "  regs R0-11:");
                for (int ri = 0; ri < 12; ri++) fprintf(cf, " %08X", NDS_ARM9.R[ri]);
                fprintf(cf, "\n  banked SVC=%08X,%08X ABT=%08X,%08X IRQ=%08X,%08X\n",
                    NDS_ARM9.R13_svc, NDS_ARM9.R14_svc,
                    NDS_ARM9.R13_abt, NDS_ARM9.R14_abt,
                    NDS_ARM9.R13_irq, NDS_ARM9.R14_irq);
                u32 sp = NDS_ARM9.R13_abt ? NDS_ARM9.R13_abt : NDS_ARM9.R13_svc;
                if (!sp || (sp >> 24) != 0x02) sp = NDS_ARM9.R13_svc;
                if (sp && (sp >> 24) == 0x02)
                {
                    fprintf(cf, "  stack@%08X:", sp);
                    for (int si = 0; si < 32; si++)
                        fprintf(cf, " %08X", apRd32(sp + si*4));
                    fprintf(cf, "\n");
                }
                fclose(cf);
                ccDumped++;
            }
        }
    }

    // ---- alarm tripwire maintenance: learn queue + armed structs, verify ----
    if (romUp && gBr.ctl)
    {
        // ctl+16 = a literal from OS_InitAlarm's pool: lands somewhere in the
        // OSi alarm BSS cluster (UseAlarm flag / queue head / valarm are
        // adjacent words).  Watch the whole neighbourhood; resolve the exact
        // queue head by probing for a word that behaves like one.
        u32 w = apRd32(gBr.ctl + 16);
        if (w >= 0x02000000 && w < 0x02400000)
        {
            u32 lo = (w - 0x10) & ~3u;
            if (sWatchQueueAddr != w)
            {
                sWatchQueueAddr = w;
                sWatchCount = 0;
                sWatchNodeCount = 0;
                sWatchHits = 0;
                sWatchRole = myRole;
                sWatchRanges[sWatchCount].lo = lo;
                sWatchRanges[sWatchCount].hi = lo + 0x48;
                sWatchCount++;
                // The whole SDK-statics band: sound arena through the card
                // library's common block (cardi_common holds the TRANSIENT
                // card alarm that is armed exactly during seam card reads —
                // the freeze victim's neighbourhood).  Positioned relative to
                // the exported literal so ROM rebuilds keep working.
                sWatchRanges[sWatchCount].lo = (w > 0x02002600) ? (w - 0x2600) : 0x02000000;
                sWatchRanges[sWatchCount].hi = w + 0x2800;
                sWatchCount++;
                gMpWatchArmed = true;
                MpWatchLog("ARMED role=%d f=%u cluster=%08X..%08X band=%08X..%08X (lit=%08X)\n",
                    myRole, gBr.frame, lo, lo + 0x48,
                    sWatchRanges[1].lo, sWatchRanges[1].hi, w);
                // Optional extra watch: "addr len" (hex) in mp_table_watch.txt
                // next to the exe — logs EVERY writer to that range with its
                // PC (the gfx entry-table biography for the shadow hunt).
                {
                    FILE* tf = fopen("mp_table_watch.txt", "r");
                    if (tf) {
                        unsigned taddr = 0, tlen = 0;
                        if (fscanf(tf, "%x %x", &taddr, &tlen) == 2
                            && taddr >= 0x02000000u && taddr < 0x02400000u
                            && tlen > 0 && tlen <= 0x1000u && sWatchCount < 20) {
                            sTableRange = sWatchCount;
                            sWatchRanges[sWatchCount].lo = taddr;
                            sWatchRanges[sWatchCount].hi = taddr + tlen;
                            sWatchCount++;
                            MpWatchLog("TABLEWATCH role=%d %08X..%08X\n", myRole, taddr, taddr + tlen);
                        }
                        fclose(tf);
                    }
                }
            }
            // Resolve the live queue head: a word in the cluster holding a
            // pointer to a sane-looking OSAlarm (handler word inside code).
            static u32 sResolvedHead = 0;
            if (!sResolvedHead)
            {
                for (u32 cand = lo; cand < lo + 0x48; cand += 4)
                {
                    u32 v = apRd32(cand);
                    if (v < 0x02000000 || v >= 0x02400000 || (v & 3)) continue;
                    u32 h = apRd32(v);                 // candidate node's handler
                    if (h >= 0x02000000 && h < 0x02400000)
                    {
                        sResolvedHead = cand;
                        MpWatchLog("QUEUE f=%u head=%08X (first node=%08X handler=%08X)\n",
                            gBr.frame, cand, v, h);
                        break;
                    }
                }
            }
            // Walk the queue; remember every armed alarm struct (sticky).
            u32 node = sResolvedHead ? apRd32(sResolvedHead) : 0;
            for (int g = 0; g < 8 && node; g++)
            {
                if (node < 0x02000000 || node >= 0x02400000 || (node & 3)) break;
                int ki = -1;
                for (int i = 0; i < sWatchNodeCount; i++)
                    if (sWatchNodes[i] == node) { ki = i; break; }
                if (ki < 0 && sWatchNodeCount < 16 && sWatchCount < 20)
                {
                    ki = sWatchNodeCount;
                    sWatchNodes[sWatchNodeCount++] = node;
                    sWatchRanges[sWatchCount].lo = node;
                    sWatchRanges[sWatchCount].hi = node + 0x2C;   // sizeof(OSAlarm)
                    sWatchCount++;
                    sNodeSnapHandler[ki] = apRd32(node);
                    MpWatchLog("NODE f=%u addr=%08X handler=%08X arg=%08X tag=%08X period=%08X%08X\n",
                        gBr.frame, node, apRd32(node), apRd32(node + 4), apRd32(node + 8),
                        apRd32(node + 0x20), apRd32(node + 0x1C));
                }
                node = apRd32(node + 0x18);   // OSAlarm.next
            }
            // Content sentinel (JIT-miss backup): a remembered struct's handler
            // must never change to garbage while we watch.
            for (int i = 0; i < sWatchNodeCount; i++)
            {
                u32 h = apRd32(sWatchNodes[i]);
                if (h != sNodeSnapHandler[i])
                {
                    MpWatchLog("CONTENT f=%u node=%08X handler %08X -> %08X period=%08X R15(9)=%08X\n",
                        gBr.frame, sWatchNodes[i], sNodeSnapHandler[i], h,
                        apRd32(sWatchNodes[i] + 0x1C), NDS_ARM9.instruct_adr);
                    sNodeSnapHandler[i] = h;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Autopilot input — melonDS apApply ported onto UserInput.
// press bits follow the melonDS numbering: 0=A 1=B 2=Select 3=Start
// 4=Right 5=Left 6=Up 7=Down 10=X 11=Y.
// ---------------------------------------------------------------------------
void MpAp_OverrideInput()
{
    if (apMode < 0) return;
    apFrame++;

    u32 press = 0;

    // ---- boot script: A through title/continue until the field runs ----
    // Suppressed under MELONDS_AP_HOLD so the operator can drive the load/menu
    // by hand (e.g. the "on my command" replay setup).
    if (apFrame >= 700 && apFrame < 2000 && !apInField && !apHold)
    {
        if ((apFrame % 40) < 8) press |= (1 << 0);
    }
    else if (!apHold && apFrame == 2120 && gBr.disc)
    {
        // debug-inbox activation (cmd 19): the SELECT shortcut is gone —
        // in-game activation lives on the "Wireless Play" bag item now.
        // Runs in LIVE mode too so a 2-instance session auto-connects; a
        // solo live instance just searches harmlessly.
        u32 inbox = apRd32(gBr.disc + 17*4);
        if (inbox)
        {
            apWr32(inbox + 12, 19);
            apWr32(inbox + 16, 1);
            apWr32(inbox + 4, apRd32(inbox + 8) + 1);
        }
    }

    // ---- LIVE INPUT (patMode 9): on-demand button presses from a command
    // file, so an operator can drive this instance one step at a time.
    // ROLE-AWARE: host reads mp_live_p1.txt, join reads mp_live_p2.txt (both
    // instances share a cwd, so each must read its own).  One line:
    //   <seq> <btn> <frames>
    // btn is one of U D L R A B X Y S(tart) T(select).  A NEW seq starts a
    // fresh hold for <frames> frames.  Re-read a few times/sec (cheap). ----
    if (patMode == 9)
    {
        static int  liveSeq = -1;
        static int  liveFramesLeft = 0;
        static u32  liveBit = 0;
        if ((apFrame & 3) == 0)
        {
            const char* lfn = (apMode == 0) ? "mp_live_p1.txt" : "mp_live_p2.txt";
            FILE* lf = fopen(lfn, "r");
            if (lf)
            {
                int seq = 0, frames = 0; char btn = 0;
                if (fscanf(lf, "%d %c %d", &seq, &btn, &frames) == 3 && seq != liveSeq)
                {
                    liveSeq = seq;
                    liveFramesLeft = (frames > 0 && frames < 600) ? frames : 1;
                    switch (btn)
                    {
                        case 'A': liveBit = (1u << 0);  break;
                        case 'B': liveBit = (1u << 1);  break;
                        case 'T': liveBit = (1u << 2);  break;  // Select
                        case 'S': liveBit = (1u << 3);  break;  // Start
                        case 'R': liveBit = (1u << 4);  break;  // d-pad Right
                        case 'L': liveBit = (1u << 5);  break;  // d-pad Left
                        case 'U': liveBit = (1u << 6);  break;
                        case 'D': liveBit = (1u << 7);  break;
                        case 'X': liveBit = (1u << 10); break;
                        case 'Y': liveBit = (1u << 11); break;
                        default:  liveBit = 0;          break;
                    }
                }
                fclose(lf);
            }
        }
        if (liveFramesLeft > 0)
        {
            press |= liveBit;
            liveFramesLeft--;
        }
    }

    if (gBr.disc)
    {
        u32 pOwExp = gBr.owExp;
        u32 pDiag = apRd32(gBr.disc + 30*4);
        // IN-GAME session mask (wm-diag peerMask), NOT the TCP link state:
        // patterns must wait for "Activate Multiplayer" to have completed.
        // (Latching on gNet.peerMask() fired at the title screen and ran the
        // whole script against a solo session.)
        u8 peerMask = pDiag ? apRd8(pDiag + 7) : 0;

        // field detection: overworld frameCounter advancing == in-field
        if (!apInField)
        {
            u32 fc = apRd32(pOwExp + 0x0C);
            if (fc != 0 && apFieldFC != 0 && fc != apFieldFC) apInField = 1;
            apFieldFC = fc;
        }

        if (!apConnFrame && peerMask)
        {
            apConnFrame = apFrame;
            printf("[AP] connected at frame %u\n", apFrame);
            fflush(stdout);
        }

        if (apConnFrame && !apHold)
        {
            u32 cf = apFrame - apConnFrame;
            u32 winLo = (apMode == 0) ? 300u : 1700u;
            u32 winHi = (apMode == 0) ? 1500u : 2900u;

            if (patMode == 4 || patMode == 5)
            {
                // Underground leave/re-enter repro (the manual recipe):
                //   both: Y (registered Explorer Kit) then A every 1s x30 -> descend
                //   leaver only: X menu, Down x5, A x4 (2s apart) -> "Go up"
                //   wait ~15s, then Y + A every 1s x30 -> descend again
                // ugclient: the JOIN instance leaves; ughost: the HOST leaves.
                bool leaver = (patMode == 4) ? (apMode == 1) : (apMode == 0);
                // 4-player: extra joiners set MELONDS_AP_NOLEAVE=1 and stand.
                static int apNoLeave = -1;
                if (apNoLeave < 0) apNoLeave = getenv("MELONDS_AP_NOLEAVE") ? 1 : 0;
                if (apNoLeave) leaver = false;

                if (cf >= 300 && cf < 308)
                    press |= (1u << 11);                                   // Y: Explorer Kit
                else if (cf >= 360 && cf < 360 + 30*60 && ((cf - 360) % 60) < 8)
                    press |= (1u << 0);                                    // A x30 (1/s)

                if (leaver)
                {
                    const u32 L = 2400;                                    // below by now
                    const u32 R = L + 240 + 4*120 + 900;                   // after up + ~15s
                    if (cf >= L && cf < L + 8)
                        press |= (1u << 10);                               // X: menu
                    else if (cf >= L + 60 && cf < L + 60 + 5*24 && ((cf - L - 60) % 24) < 8)
                        press |= (1u << 7);                                // Down x5
                    else if (cf >= L + 240 && cf < L + 240 + 4*120 && ((cf - L - 240) % 120) < 8)
                        press |= (1u << 0);                                // A x4 (2s apart)
                    else if (cf >= R && cf < R + 8)
                        press |= (1u << 11);                               // Y again
                    else if (cf >= R + 60 && cf < R + 60 + 30*60 && ((cf - R - 60) % 60) < 8)
                        press |= (1u << 0);                                // A x30: re-descend
                }
            }
            else if (patMode <= 3 && cf >= winLo && cf < winHi)
            {
                // Default wander patterns (0 walk / 1 run / 2 circle / 3
                // waggle) ONLY.  Was ungated, so it shadowed the scripted
                // patterns 6/7/8 during the window -> host wandered L/R, join
                // wandered U/D, and the real recipe never ran.
                if (patMode == 3)
                {
                    u32 pc = (cf - winLo) % 510;
                    int bitA = (apMode == 0) ? 5 : 6;
                    int bitB = (apMode == 0) ? 4 : 7;
                    if (pc < 240)
                    {
                        press |= (1 << 1);
                        press |= (1 << (((pc / 8) & 1) ? bitA : bitB));
                    }
                    else if (pc < 420)
                    {
                        press |= (1 << 1);
                        press |= (1 << ((((cf - winLo) / 510) & 1) ? bitB : bitA));
                    }
                }
                else if (patMode == 2)
                {
                    static const int circleBit[4] = { 4, 7, 5, 6 };
                    press |= (1 << 1);
                    press |= (1 << circleBit[(cf / 32) & 3]);
                }
                else
                {
                    if (patMode == 1) press |= (1 << 1);
                    if (apMode == 0)
                        press |= (1 << (((cf / 90) & 1) ? 5 : 4));
                    else
                        press |= (1 << (((cf / 90) & 1) ? 7 : 6));
                }
            }
            else if (patMode == 6)
            {
                // STARTER-CRASH repro (user recipe): both saves sit AT the
                // briefcase scene.  Once connected, P1 (host) presses A once
                // a second for ~10s to advance into starter select; P2 idles.
                if (apMode == 0 && cf >= 300 && cf < 300 + 10*60 && ((cf - 300) % 60) < 8)
                    press |= (1u << 0);                                    // A
            }
            else if (patMode == 7)
            {
                // SEAM-WALK repro (user recipe), made DETERMINISTIC.  The
                // options-menu navigation was fragile (start-menu layout
                // varies -> Down x4 missed Options -> no swap, just walking).
                // Instead P1 swaps its appearance straight through the debug
                // inbox (cmd 20 = set appearance byte) to HILBERT (type 8) --
                // a known shadow-prone native-model character -- then P2
                // steps one tile UP through the seam and one tile back DOWN.
                if (apMode == 0)
                {
                    static int apSwapSent = 0;
                    if (cf >= 600 && !apSwapSent && gBr.disc)
                    {
                        u32 inbox = apRd32(gBr.disc + 17 * 4);
                        if (inbox)
                        {
                            apWr32(inbox + 12, 20);        // cmd 20 = set appearance
                            apWr32(inbox + 16, 0x81);      // Hilbert (type 8), colour 1
                            apWr32(inbox + 4, apRd32(inbox + 8) + 1);  // seq = ackSeq+1
                            apSwapSent = 1;
                            printf("[AP] seam: appearance swap -> Hilbert sent at cf=%u\n", cf);
                            fflush(stdout);
                        }
                    }
                }
                else
                {
                    // Walk DECISIVELY across the seam and a few tiles beyond so
                    // P2 settles clearly on the new map (not straddling the
                    // boundary, which oscillated the map header ~16x and never
                    // let the partner settle).  Long single hold, stop, hold
                    // back.  ~72 frames ~= 4-5 tiles (walls just stop us).
                    if (cf >= 1100 && cf < 1172)        press |= (1u << 6);    // Up x~5 (cross + settle)
                    else if (cf >= 1600 && cf < 1672)   press |= (1u << 7);    // Down x~5 (back + settle)
                }
            }
            else if (patMode == 8)
            {
                // BANNER-REFRESH repro (user recipe): both instances boot the
                // SAME pokeplatinumtest save, so they start ON THE SAME TILE
                // already facing DOWN.  P2 steps one tile DOWN -> lands right
                // in front of P1 (P1 is already facing down, no turn needed).
                // P1 presses A three times -> partner menu -> Battle,
                // challenging P2.  P2 (join, role 2) is the ACCEPTER whose
                // "<name> has challenged you!" banner refreshes.
                if (apMode == 1)
                {
                    // brief tap: already facing down, so ~7 frames = exactly
                    // ONE step (24 frames over-shot and left the house).
                    if (cf >= 300 && cf < 307)          press |= (1u << 7);    // P2: Down one tile
                    // AFTER the challenge lands (~cf 700), walk left/right in
                    // place -- the reported refresh only happens while the
                    // accepter MOVES, so this exercises it for the diag.
                    else if (cf >= 800)                 press |= (1u << (((cf / 30) & 1) ? 5 : 4)); // L/R
                }
                else
                {
                    if (cf >= 500 && cf < 508)          press |= (1u << 0);    // A: open partner menu
                    else if (cf >= 580 && cf < 588)     press |= (1u << 0);    // A: Battle
                    else if (cf >= 660 && cf < 668)     press |= (1u << 0);    // A: confirm/extra
                }
            }
        }

        // telemetry CSV
        if (!apCsv)
        {
            char name[64];
            snprintf(name, sizeof(name), "desmume_ap_%s.csv", (apMode == 0) ? "host" : "join");
            apCsv = fopen(name, "w");
            if (apCsv) fprintf(apCsv, "frame,peerMask,ownX,ownZ,ownFC,i0FC,i1FC\n");
        }
        if (apCsv && gBr.owExp && gBr.owImp)
        {
            fprintf(apCsv, "%u,%u,%d,%d,%u,%u,%u\n",
                apFrame, peerMask,
                apRd16s(gBr.owExp + 4), apRd16s(gBr.owExp + 6), apRd32(gBr.owExp + 0x0C),
                apRd32(gBr.owImp + 0x0C), apRd32(gBr.owImp + 48 + 0x0C));
            if ((apFrame & 255) == 0) fflush(apCsv);
        }

        // per-role hang sampler (game FC frozen while connected)
        {
            static u32 lastFC = 0, lastChangeAt = 0, dumped = 0;
            u32 fcNow = apRd32(pOwExp + 0x0C);
            if (fcNow != lastFC) { lastFC = fcNow; lastChangeAt = apFrame; dumped = 0; }
            else if (apConnFrame && apFrame - lastChangeAt > 180 && dumped < 64)
            {
                char hn[64];
                snprintf(hn, sizeof(hn), "desmume_hangpc_%s.txt", (apMode == 0) ? "host" : "join");
                FILE* hf = fopen(hn, "a");
                if (hf)
                {
                    fprintf(hf, "f=%u FCstuck=%u R15=%08X R14=%08X R13=%08X R12=%08X CPSR=%08X\n",
                        apFrame, fcNow,
                        NDS_ARM9.instruct_adr, NDS_ARM9.R[14], NDS_ARM9.R[13], NDS_ARM9.R[12],
                        NDS_ARM9.CPSR.val);
                    fclose(hf);
                    dumped++;
                }
            }
        }
    }

    // ---- INPUT RECORD (patMode 10) / REPLAY (patMode 11) ----------------
    // Record auto-arms at overworld entry and logs the user's real pad
    // on-change.  Replay instead waits for an operator go-signal file
    // (mp_replay_go.txt) and then plays the recording from the character's
    // CURRENT position -- the operator loads the save + connects by hand first
    // (MELONDS_AP_HOLD suppresses auto-boot/-connect), so playback never fights
    // that setup.  The go file is one-shot (removed on trigger).
    if (patMode == 10 && apInField)
    {
        if (!apRecStarted)
        {
            apRecStarted = 1; apAnchorFrame = apFrame;
            apRecFile = fopen("mp_record.txt", "w"); apRecLastMask = 0xFFFFFFFFu;
            printf("[AP] recording input -> mp_record.txt\n"); fflush(stdout);
        }
        u32 ff = apFrame - apAnchorFrame;
        UserInput& uin = NDS_getProcessingUserInput();
        u32 mask = 0;
        if (uin.buttons.A) mask |= (1u << 0);
        if (uin.buttons.B) mask |= (1u << 1);
        if (uin.buttons.T) mask |= (1u << 2);
        if (uin.buttons.S) mask |= (1u << 3);
        if (uin.buttons.R) mask |= (1u << 4);
        if (uin.buttons.L) mask |= (1u << 5);
        if (uin.buttons.U) mask |= (1u << 6);
        if (uin.buttons.D) mask |= (1u << 7);
        if (uin.buttons.X) mask |= (1u << 10);
        if (uin.buttons.Y) mask |= (1u << 11);
        if (apRecFile && mask != apRecLastMask)
        { fprintf(apRecFile, "%u %u\n", ff, mask); fflush(apRecFile); apRecLastMask = mask; }
        return;   // record never overrides the user's live input
    }
    else if (patMode == 11)
    {
        if (!apRecStarted)
        {
            if ((apFrame & 7) == 0)   // poll the go-signal ~7x/sec
            {
                FILE* tf = fopen("mp_replay_go.txt", "r");
                if (tf)
                {
                    fclose(tf); remove("mp_replay_go.txt");
                    apRecStarted = 1; apAnchorFrame = apFrame;
                    apRepCount = apRepIdx = 0; apRepMask = 0;
                    FILE* rf = fopen("mp_record.txt", "r");
                    if (rf)
                    {
                        u32 fr, mk;
                        while (apRepCount < AP_REP_MAX && fscanf(rf, "%u %u", &fr, &mk) == 2)
                        { apRepTab[apRepCount].f = fr; apRepTab[apRepCount].mask = mk; apRepCount++; }
                        fclose(rf);
                    }
                    printf("[AP] replay triggered: %d events\n", apRepCount); fflush(stdout);
                }
            }
        }
        if (apRecStarted)
        {
            u32 ff = apFrame - apAnchorFrame;
            while (apRepIdx < apRepCount && apRepTab[apRepIdx].f <= ff)
            { apRepMask = apRepTab[apRepIdx].mask; apRepIdx++; }
            press |= apRepMask;
        }
    }

    if (!press && !apTouchFrames) return;

    UserInput& in = NDS_getProcessingUserInput();
    if (apTouchFrames > 0)
    {
        // scripted stylus press: the options appearance RIGHT arrow
        apTouchFrames--;
        in.touch.touchX = 230;
        in.touch.touchY = 151;
        in.touch.isTouch = true;
    }
    if (press & (1 << 0))  in.buttons.A = true;
    if (press & (1 << 1))  in.buttons.B = true;
    if (press & (1 << 2))  in.buttons.T = true;   // select
    if (press & (1 << 3))  in.buttons.S = true;   // start
    if (press & (1 << 4))  in.buttons.R = true;   // d-pad right
    if (press & (1 << 5))  in.buttons.L = true;   // d-pad left
    if (press & (1 << 6))  in.buttons.U = true;
    if (press & (1 << 7))  in.buttons.D = true;
    if (press & (1 << 10)) in.buttons.X = true;
    if (press & (1 << 11)) in.buttons.Y = true;
}
// MARKER_TEST
