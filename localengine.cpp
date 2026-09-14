/*
 * =====================================================================
 *  LOCAL C++ REAL-TIME ENGINE  (Live Traffic Path)
 *  AI-Assisted Email Cryptographic Forensics Framework
 * =====================================================================
 *
 *  Pipeline implemented in this single file (matches architecture diagram):
 *    1. Packet Capture           (libpcap / Npcap)
 *    2. Protocol Identification  (SMTP / IMAP / POP3 by port + banner, PLUS
 *                                 HTTPS/443 mail traffic classified by TLS
 *                                 SNI -> Outlook 365 / Gmail. Modern Outlook
 *                                 and Gmail clients don't use classic
 *                                 SMTP/IMAP/POP3 ports at all -- they are
 *                                 TLS-encrypted from byte 0 on port 443, so
 *                                 they were previously invisible to this
 *                                 engine. SNI is read in cleartext from the
 *                                 ClientHello -- no decryption is done.)
 *    3. STARTTLS Detection       (plaintext command + TLS handshake check;
 *                                 N/A for 443 traffic, which is TLS already)
 *    4. Heuristic Checks         (fast rules: stripped STARTTLS, weak/legacy
 *                                 TLS version in ClientHello, plaintext creds)
 *    5. Suspicious Event Decision (YES/NO gate)
 *    6. Fast Local Actions        (instant console alert, temp block flag,
 *                                 local logging to file)
 *    7. Send Suspicious Event to Cloud (HTTPS POST -> FastAPI /api/events)
 *
 *  This is a DEFENSIVE monitoring tool: it only observes traffic on an
 *  interface you own/administer and flags weak or stripped TLS setups
 *  in mail protocols. It does not decrypt, inject, or tamper with traffic.
 *
 *  ---------------------------------------------------------------
 *  BUILD (Linux):
 *      sudo apt-get install libpcap-dev libcurl4-openssl-dev
 *      g++ -O2 -std=c++17 local_realtime_engine.cpp -o rt_engine \
 *          -lpcap -lcurl -lpthread
 *
 *  RUN (needs root / CAP_NET_RAW to sniff):
 *      sudo ./rt_engine <interface> <cloud_endpoint_url>
 *      sudo ./rt_engine eth0 https://your-cloud-host/api/events
 *
 *  BUILD (Windows, matches diagram's "Packet Capture (Winsock/Npcap)"):
 *      1. Install Npcap + Npcap SDK (https://npcap.com) — ships WinPcap-
 *         compatible pcap.h and wpcap.lib/Packet.lib.
 *      2. Install libcurl for Windows (or vcpkg: vcpkg install curl).
 *      3. Compile with MSVC or MinGW, e.g. (MinGW):
 *           g++ -O2 -std=c++17 local_realtime_engine.cpp -o rt_engine.exe ^
 *               -I"C:\Npcap-SDK\Include" -L"C:\Npcap-SDK\Lib\x64" ^
 *               -lwpcap -lPacket -lws2_32 -lcurl
 *      4. Run as Administrator: rt_engine.exe "\Device\NPF_{...}" <url>
 *         (use `pcap_findalldevs` output, or Npcap's device list, for the
 *         interface string).
 *
 *  This file defines its OWN Ethernet/IPv4/TCP header structs below
 *  instead of relying on Linux's <netinet/*.h>, so the exact same
 *  packetHandler() logic compiles unmodified on both platforms —
 *  only the socket-library init (Winsock) differs, guarded by #ifdef _WIN32.
 *  ---------------------------------------------------------------
 */

#include <pcap.h>
#include <curl/curl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h> // ntohs/ntohl, inet_ntoa, struct in_addr
#endif

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <ctime>
#include <csignal>
#include <vector>

// =====================================================================
// Portable packet header layouts (works on Linux + Windows identically —
// avoids depending on Linux-only <netinet/if_ether.h|ip.h|tcp.h>)
// =====================================================================
#pragma pack(push, 1)
struct EthHeader
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype; // network byte order; 0x0800 = IPv4
};

struct IPv4Header
{
    uint8_t ver_ihl; // upper nibble = version(4), lower = header len (in 32-bit words)
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol; // 6 = TCP
    uint16_t checksum;
    uint32_t src_addr; // network byte order
    uint32_t dst_addr; // network byte order
};

struct TcpHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset; // upper nibble = header len in 32-bit words
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
#pragma pack(pop)

static const uint16_t ETHERTYPE_IPV4 = 0x0800;
static const uint8_t IP_PROTO_TCP = 6;

// =====================================================================
// Globals / config
// =====================================================================

static std::atomic<bool> g_running{true};
static std::string g_cloud_endpoint = "https://cyber-shield-api-fow4.onrender.com/api/events"; // FastAPI
static std::string g_heartbeat_endpoint = "https://cyber-shield-api-fow4.onrender.com/api/engine/heartbeat";
static std::string g_capture_interface;
static std::mutex g_log_mutex;
static const char *LOG_FILE = "rt_engine_events.log";

// Ports we care about: SMTP(25,587), SMTPS(465), IMAP(143), IMAPS(993),
// POP3(110), POP3S(995), plus 443 (HTTPS) for modern mail clients such as
// Outlook 365 (Exchange/MAPI-over-HTTP, Graph API) and Gmail (webmail /
// Gmail app / Gmail API) which never touch classic SMTP/IMAP/POP3 ports
// at all -- they ride entirely over HTTPS to Microsoft/Google endpoints.
static bool isMonitoredPort(uint16_t port)
{
    switch (port)
    {
    case 25:
    case 587:
    case 465:
    case 143:
    case 993:
    case 110:
    case 995:
    case 443:
        return true;
    default:
        return false;
    }
}

// =====================================================================
// 2. PROTOCOL IDENTIFICATION
// =====================================================================
static std::string identifyProtocol(uint16_t port)
{
    switch (port)
    {
    case 25:
    case 587:
        return "SMTP";
    case 465:
        return "SMTPS(implicit-TLS)";
    case 143:
        return "IMAP";
    case 993:
        return "IMAPS(implicit-TLS)";
    case 110:
        return "POP3";
    case 995:
        return "POP3S(implicit-TLS)";
    case 443:
        return "HTTPS(pending-SNI)"; // resolved to Outlook365/Gmail/etc via SNI
    default:
        return "UNKNOWN";
    }
}

// =====================================================================
// Flow tracking (very lightweight TCP stream reconstruction)
// =====================================================================
struct FlowKey
{
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    bool operator<(const FlowKey &o) const
    {
        if (src_ip != o.src_ip)
            return src_ip < o.src_ip;
        if (dst_ip != o.dst_ip)
            return dst_ip < o.dst_ip;
        if (src_port != o.src_port)
            return src_port < o.src_port;
        return dst_port < o.dst_port;
    }
};

struct FlowState
{
    std::string protocol;
    bool starttlsCommandSeen = false; // client sent "STARTTLS"
    bool serverAckedStarttls = false; // server replied 220 / +OK / OK
    bool tlsHandshakeSeen = false;    // saw 0x16 0x03 record after ack
    bool implicitTls = false;         // port itself implies TLS (465/993/995)
    bool alreadyFlagged = false;
    bool normalLogged = false; // Quick-Allow already recorded for this flow
    double firstSeen = 0, lastSeen = 0;
    std::string clientHelloVersion; // e.g. "TLS 1.0 (weak)"

    // --- Port-443 (HTTPS) mail classification ---
    // Outlook 365 / Gmail apps never touch classic SMTP/IMAP/POP3 ports;
    // they are TLS from byte 0 on port 443. We resolve WHICH service a
    // 443 flow belongs to by reading the SNI hostname out of the
    // ClientHello (sent in cleartext by design -- no decryption involved),
    // then keep or drop the flow from monitoring based on that.
    bool pendingSni = false;  // true until we've inspected the ClientHello
    bool ignored = false;     // true = confirmed non-mail HTTPS, stop looking
    std::string sniHostname;  // resolved server_name, e.g. outlook.office365.com
    std::string mailProvider; // "Outlook365" / "Gmail" / "" (unknown)
};

static std::map<FlowKey, FlowState> g_flows;
static std::mutex g_flows_mutex;
static std::atomic<uint64_t> g_quickAllowCount{0}; // flows marked Normal / Quick Allow

static double nowSeconds()
{
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

static std::string isoTimestamp()
{
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return std::string(buf);
}

static std::string ipToStr(uint32_t ip_be)
{
    // ip_be is already in network byte order (as read off the wire).
    struct in_addr a;
    memcpy(&a, &ip_be, sizeof(a));
    return std::string(inet_ntoa(a)); // works with both winsock2.h and arpa/inet.h
}

// =====================================================================
// libcurl helper: POST JSON to cloud FastAPI endpoint
// =====================================================================
static size_t curlWriteSink(void * /*ptr*/, size_t size, size_t nmemb, void *)
{
    return size * nmemb; // discard response body, we only care about status
}

static bool sendToCloud(const std::string &jsonPayload)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return false;

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, g_cloud_endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)jsonPayload.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteSink);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK)
    {
        std::cerr << "[CLOUD-SEND-FAIL] " << curl_easy_strerror(res) << "\n";
        return false;
    }
    return httpCode >= 200 && httpCode < 300;
}

static bool postJsonTo(const std::string &url, const std::string &jsonPayload)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return false;

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)jsonPayload.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteSink);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return res == CURLE_OK && httpCode >= 200 && httpCode < 300;
}

static std::string jsonEscape(const std::string &v)
{
    std::string out;
    out.reserve(v.size() + 8);
    for (char c : v)
    {
        if (c == '\\' || c == '"')
            out.push_back('\\');
        if (c == '\n')
        {
            out += "\\n";
            continue;
        }
        if (c == '\r')
        {
            out += "\\r";
            continue;
        }
        out.push_back(c);
    }
    return out;
}

static void engineHeartbeatLoop()
{
    using namespace std::chrono_literals;
    while (g_running.load())
    {
        std::ostringstream j;
        j << "{\"engine_source\":\"local_cpp\",\"status\":\"online\",\"interface\":\""
          << jsonEscape(g_capture_interface) << "\"}";
        bool ok = postJsonTo(g_heartbeat_endpoint, j.str());
        std::cout << (ok ? "[HEARTBEAT] ONLINE -> backend\n" : "[HEARTBEAT-FAIL] Could not reach backend\n");
        std::this_thread::sleep_for(5s);
    }
}

// =====================================================================
// Local logging (6. Fast Local Actions -> Local Logging)
// =====================================================================
static void logLocally(const std::string &line)
{
    std::lock_guard<std::mutex> lk(g_log_mutex);
    std::ofstream out(LOG_FILE, std::ios::app);
    if (out)
        out << line << "\n";
}

// =====================================================================
// 6. FAST LOCAL ACTIONS (Instant Alert / Temporary Block / Local Logging)
// =====================================================================
static void fastLocalActions(const std::string &reason,
                             const std::string &srcIp, uint16_t srcPort,
                             const std::string &dstIp, uint16_t dstPort,
                             bool critical)
{
    std::ostringstream msg;
    msg << "[" << isoTimestamp() << "] ALERT: " << reason
        << "  " << srcIp << ":" << srcPort << " -> " << dstIp << ":" << dstPort;

    std::cout << "\n\033[1;31m*** SUSPICIOUS EVENT ***\033[0m\n"
              << msg.str() << "\n";

    if (critical)
    {
        // Simulated temporary block: in production this would call
        // platform firewall APIs (iptables/nftables/Windows Filtering
        // Platform). We only log the intent here — no destructive action.
        std::cout << "[FAST-ACTION] Temporary block flagged for "
                  << srcIp << " (would be enforced by firewall integration)\n";
    }

    logLocally(msg.str());
}

// =====================================================================
// 5. "NO" BRANCH — MARK AS NORMAL (QUICK ALLOW)
//    Mirrors the diagram's green "NO -> Mark as Normal (Quick Allow)" path.
//    Logged once per flow (not per-packet) to avoid spamming the console
//    and log file, since the vast majority of traffic is normal.
// =====================================================================
static void markAsNormal(const FlowKey &key, FlowState &fs)
{
    if (fs.normalLogged || fs.alreadyFlagged)
        return;
    fs.normalLogged = true;
    g_quickAllowCount.fetch_add(1, std::memory_order_relaxed);

    std::ostringstream msg;
    msg << "[" << isoTimestamp() << "] QUICK-ALLOW (normal): " << fs.protocol << "  "
        << ipToStr(key.src_ip) << ":" << key.src_port << " -> "
        << ipToStr(key.dst_ip) << ":" << key.dst_port;
    if (!fs.sniHostname.empty())
        msg << "  SNI=" << fs.sniHostname;

    // Quick Allow is a lightweight, non-blocking action: local log only,
    // no console noise, no cloud round-trip (unlike suspicious events).
    logLocally(msg.str());
}

// =====================================================================
// 4. HEURISTIC CHECKS
//    - Detect STARTTLS "stripping": client asked for STARTTLS, server
//      acknowledged, but no TLS handshake record ever followed and
//      plaintext protocol traffic continued instead.
//    - Detect weak/legacy TLS version advertised in ClientHello.
// =====================================================================

// Very small helper: does buffer start a TLS record (Handshake=0x16) with
// a ClientHello (type 0x01) and legacy_version bytes readable?
static bool parseClientHelloVersion(const uint8_t *data, size_t len,
                                    std::string &versionOut)
{
    // TLS record header: [0]=ContentType(0x16) [1:2]=record version [3:4]=len
    if (len < 9)
        return false;
    if (data[0] != 0x16)
        return false; // not a handshake record
    if (data[5] != 0x01)
        return false; // not ClientHello

    uint8_t verMajor = data[9];
    uint8_t verMinor = data[10];
    if (verMajor == 0x03)
    {
        switch (verMinor)
        {
        case 0x00:
            versionOut = "SSLv3 (INSECURE)";
            return true;
        case 0x01:
            versionOut = "TLS 1.0 (weak/deprecated)";
            return true;
        case 0x02:
            versionOut = "TLS 1.1 (weak/deprecated)";
            return true;
        case 0x03:
            versionOut = "TLS 1.2 (acceptable)";
            return true;
        case 0x04:
            versionOut = "TLS 1.3 (strong)";
            return true;
        default:
            versionOut = "Unknown TLS minor version";
            return true;
        }
    }
    return false;
}

static bool containsCI(const std::string &hay, const std::string &needle)
{
    std::string h = hay, n = needle;
    for (auto &c : h)
        c = toupper((unsigned char)c);
    for (auto &c : n)
        c = toupper((unsigned char)c);
    return h.find(n) != std::string::npos;
}

// =====================================================================
// SNI (Server Name Indication) extraction from a TLS ClientHello.
// The hostname is sent in CLEARTEXT as part of the handshake (that's
// how the server picks which certificate to present) -- reading it is
// standard passive traffic-classification, not decryption. This is how
// we tell "this is an Outlook/Gmail HTTPS session" apart from ordinary
// web browsing on port 443, without ever touching the encrypted payload.
//
// NOTE: if the client negotiates Encrypted Client Hello (ECH), the SNI
// will be hidden. As of now Outlook/Gmail native apps and Exchange/Gmail
// endpoints do not enable ECH by default, so this works in practice, but
// it is a known blind spot worth knowing about.
// =====================================================================
static bool parseSNI(const uint8_t *data, size_t len, std::string &sniOut)
{
    if (len < 43)
        return false;
    if (data[0] != 0x16)
        return false; // not a TLS handshake record
    if (data[5] != 0x01)
        return false; // not a ClientHello

    size_t recordEnd = 5 + (((size_t)data[3] << 8) | data[4]);
    if (recordEnd > len)
        recordEnd = len;

    size_t p = 5; // start of Handshake message
    if (p + 4 > recordEnd)
        return false;
    size_t hsLen = ((size_t)data[p + 1] << 16) | ((size_t)data[p + 2] << 8) | data[p + 3];
    p += 4; // now at handshake body (client_version)
    size_t hsEnd = p + hsLen;
    if (hsEnd > recordEnd)
        hsEnd = recordEnd;

    if (p + 2 + 32 > hsEnd)
        return false;
    p += 2;  // client_version
    p += 32; // random

    if (p + 1 > hsEnd)
        return false;
    uint8_t sessIdLen = data[p];
    p += 1 + sessIdLen;

    if (p + 2 > hsEnd)
        return false;
    uint16_t cipherLen = ((uint16_t)data[p] << 8) | data[p + 1];
    p += 2 + cipherLen;

    if (p + 1 > hsEnd)
        return false;
    uint8_t compLen = data[p];
    p += 1 + compLen;

    if (p + 2 > hsEnd)
        return false;
    uint16_t extTotalLen = ((uint16_t)data[p] << 8) | data[p + 1];
    p += 2;
    size_t extEnd = p + extTotalLen;
    if (extEnd > hsEnd)
        extEnd = hsEnd;

    while (p + 4 <= extEnd)
    {
        uint16_t extType = ((uint16_t)data[p] << 8) | data[p + 1];
        uint16_t extLen = ((uint16_t)data[p + 2] << 8) | data[p + 3];
        size_t extBody = p + 4;
        if (extBody + extLen > extEnd)
            break;

        if (extType == 0x0000 && extLen >= 5) // server_name extension
        {
            size_t q = extBody + 2; // skip server_name_list length (2 bytes)
            if (q + 3 <= extBody + extLen && data[q] == 0x00 /* host_name type */)
            {
                uint16_t nameLen = ((uint16_t)data[q + 1] << 8) | data[q + 2];
                size_t nameStart = q + 3;
                if (nameStart + nameLen <= extBody + extLen)
                {
                    sniOut.assign(reinterpret_cast<const char *>(data + nameStart), nameLen);
                    return true;
                }
            }
        }
        p = extBody + extLen;
    }
    return false;
}

// Known hostname fragments used by Outlook/Microsoft 365 and Gmail/Google
// mail services. Substring match on the SNI hostname is enough here --
// we're doing coarse traffic classification, not certificate pinning.
static std::string classifyMailProvider(const std::string &sni)
{
    static const std::vector<std::string> kOutlook = {
        "outlook.office365.com", "outlook.office.com", "smtp.office365.com",
        "imap-mail.outlook.com", "pop-mail.outlook.com", "outlook.live.com",
        "outlook.com", "login.microsoftonline.com", "autodiscover",
        "graph.microsoft.com", "protection.outlook.com", "office365.com"};
    static const std::vector<std::string> kGmail = {
        "mail.google.com", "smtp.gmail.com", "imap.gmail.com", "pop.gmail.com",
        "gmail.googleapis.com", "accounts.google.com", "googleapis.com"};

    for (const auto &d : kOutlook)
        if (containsCI(sni, d))
            return "Outlook365";
    for (const auto &d : kGmail)
        if (containsCI(sni, d))
            return "Gmail";
    return "";
}

// =====================================================================
// Cloud push helper: build JSON for a suspicious event and send it
// =====================================================================
static void sendSuspiciousEventToCloud(const FlowKey &key, const FlowState &fs,
                                       const std::string &reason)
{
    std::ostringstream j;
    j << "{"
      << "\"engine_source\":\"local_cpp_realtime\","
      << "\"scan_mode\":\"live\","
      << "\"timestamp\":\"" << isoTimestamp() << "\","
      << "\"protocol\":\"" << fs.protocol << "\","
      << "\"src_ip\":\"" << ipToStr(key.src_ip) << "\","
      << "\"src_port\":" << key.src_port << ","
      << "\"dst_ip\":\"" << ipToStr(key.dst_ip) << "\","
      << "\"dst_port\":" << key.dst_port << ","
      << "\"reason\":\"" << reason << "\","
      << "\"starttls_command_seen\":" << (fs.starttlsCommandSeen ? "true" : "false") << ","
      << "\"server_acked_starttls\":" << (fs.serverAckedStarttls ? "true" : "false") << ","
      << "\"tls_handshake_seen\":" << (fs.tlsHandshakeSeen ? "true" : "false") << ","
      << "\"tls_client_hello_version\":\""
      << (fs.clientHelloVersion.empty() ? "unknown" : fs.clientHelloVersion) << "\","
      << "\"sni_hostname\":\"" << jsonEscape(fs.sniHostname) << "\","
      << "\"mail_provider\":\"" << (fs.mailProvider.empty() ? "unknown" : fs.mailProvider) << "\""
      << "}";

    bool ok = sendToCloud(j.str());
    std::cout << "[CLOUD] Suspicious event push "
              << (ok ? "OK" : "FAILED (will retain in local log)") << "\n";
    if (!ok)
        logLocally(std::string("[CLOUD-SEND-FAILED] ") + j.str());
}

// =====================================================================
// 5. SUSPICIOUS EVENT DECISION  (the diamond in the diagram)
// =====================================================================
static void evaluateFlow(const FlowKey &key, FlowState &fs)
{
    if (fs.alreadyFlagged)
        return;

    // Heuristic A: STARTTLS requested + acked, but no TLS handshake
    // followed within this flow while more plaintext data kept moving.
    // => classic STARTTLS-stripping / downgrade attack indicator.
    if (fs.starttlsCommandSeen && fs.serverAckedStarttls && !fs.tlsHandshakeSeen)
    {
        fs.alreadyFlagged = true;
        fastLocalActions("STARTTLS command acknowledged but no TLS handshake "
                         "followed (possible STARTTLS-stripping / downgrade attack)",
                         ipToStr(key.src_ip), key.src_port,
                         ipToStr(key.dst_ip), key.dst_port, /*critical=*/true);
        sendSuspiciousEventToCloud(key, fs, "starttls_stripping_suspected");
        return;
    }

    // Heuristic B: weak/legacy TLS version in ClientHello.
    if (!fs.clientHelloVersion.empty() &&
        (containsCI(fs.clientHelloVersion, "SSLv3") ||
         containsCI(fs.clientHelloVersion, "TLS 1.0") ||
         containsCI(fs.clientHelloVersion, "TLS 1.1")))
    {
        fs.alreadyFlagged = true;
        fastLocalActions("Weak/legacy TLS version offered: " + fs.clientHelloVersion,
                         ipToStr(key.src_ip), key.src_port,
                         ipToStr(key.dst_ip), key.dst_port, /*critical=*/false);
        sendSuspiciousEventToCloud(key, fs, "weak_tls_version");
        return;
    }

    // NO suspicious pattern matched yet for this flow -> diagram's
    // "Mark as Normal (Quick Allow)" branch.
    markAsNormal(key, fs);
}

// =====================================================================
// 3. STARTTLS DETECTION + payload analysis
// =====================================================================
static void analyzePayload(const FlowKey &key, FlowState &fs,
                           const uint8_t *payload, size_t len, bool fromClient)
{
    if (len == 0)
        return;
    if (fs.ignored)
        return; // confirmed non-mail HTTPS earlier -- stop wasting cycles on it
    fs.lastSeen = nowSeconds();

    // --- Port-443 flows: resolve WHICH service this is via SNI first. ---
    // Only the client's ClientHello carries the SNI, so we only look at
    // client->server packets here. Until resolved, we don't run any of the
    // mail heuristics below (there's nothing sensible to check yet).
    if (fs.pendingSni)
    {
        if (!fromClient)
            return; // wait for the client's ClientHello

        std::string sni;
        if (!parseSNI(payload, len, sni))
            return; // ClientHello not fully captured in this packet yet; wait

        fs.sniHostname = sni;
        fs.mailProvider = classifyMailProvider(sni);
        fs.pendingSni = false;

        if (fs.mailProvider.empty())
        {
            // Ordinary HTTPS traffic (web browsing, other apps) -- not what
            // this forensics tool is for. Drop it quietly and permanently.
            fs.ignored = true;
            return;
        }

        // Confirmed Outlook 365 / Gmail traffic over HTTPS. Announce it now
        // (we deliberately didn't log FLOW-NEW earlier to avoid spamming the
        // console with every unrelated HTTPS connection on the box).
        fs.protocol = "HTTPS-MAIL(" + fs.mailProvider + ")";
        std::cout << "[FLOW-NEW] " << fs.protocol << "  SNI=" << fs.sniHostname << "  "
                  << ipToStr(key.src_ip) << ":" << key.src_port << " <-> "
                  << ipToStr(key.dst_ip) << ":" << key.dst_port << "\n";

        // The ClientHello also tells us the offered TLS version -- still the
        // only meaningful "heuristic check" available here, since Outlook 365
        // / Gmail never do STARTTLS: they're TLS-encrypted from byte 0, so
        // STARTTLS-stripping simply doesn't apply to this transport.
        std::string ver;
        if (parseClientHelloVersion(payload, len, ver))
            fs.clientHelloVersion = ver;
        fs.tlsHandshakeSeen = true;
        evaluateFlow(key, fs);
        return;
    }

    // If this port is implicit-TLS (465/993/995), traffic is TLS from the
    // very first byte, and STARTTLS negotiation doesn't apply.
    if (fs.implicitTls)
    {
        std::string ver;
        if (parseClientHelloVersion(payload, len, ver))
        {
            fs.tlsHandshakeSeen = true;
            fs.clientHelloVersion = ver;
        }
        evaluateFlow(key, fs);
        return;
    }

    // Try TLS record detection first (in case handshake already started).
    std::string ver;
    if (parseClientHelloVersion(payload, len, ver))
    {
        fs.tlsHandshakeSeen = true;
        fs.clientHelloVersion = ver;
        evaluateFlow(key, fs);
        return;
    }
    if (len >= 1 && payload[0] == 0x16)
    {
        // A TLS record but not necessarily ClientHello (e.g. ServerHello
        // or later handshake message) -- still counts as "handshake seen".
        fs.tlsHandshakeSeen = true;
        evaluateFlow(key, fs);
        return;
    }

    // Otherwise, treat as plaintext line-based protocol chatter.
    std::string text(reinterpret_cast<const char *>(payload), len);

    if (fromClient)
    {
        if (containsCI(text, "STARTTLS"))
        {
            fs.starttlsCommandSeen = true;
        }
    }
    else
    {
        // Server-side acknowledgements differ per protocol:
        //   SMTP: "220 Ready to start TLS" / "220 2.0.0"
        //   IMAP: "OK Begin TLS negotiation"
        //   POP3: "+OK"
        if (fs.starttlsCommandSeen && !fs.serverAckedStarttls)
        {
            if (containsCI(text, "220") || containsCI(text, "+OK") ||
                containsCI(text, " OK"))
            {
                fs.serverAckedStarttls = true;
            }
        }
    }

    // If STARTTLS was acked and plaintext protocol data keeps flowing
    // instead of a TLS handshake, that's the stripping heuristic.
    evaluateFlow(key, fs);
}

// =====================================================================
// 1. PACKET CAPTURE  (libpcap callback)
// =====================================================================
static void packetHandler(u_char * /*user*/, const struct pcap_pkthdr *header,
                          const u_char *packet)
{
    // --- Ethernet header ---
    if (header->caplen < sizeof(EthHeader))
        return;
    const EthHeader *eth = reinterpret_cast<const EthHeader *>(packet);
    if (ntohs(eth->ethertype) != ETHERTYPE_IPV4)
        return;

    const uint8_t *ipStart = packet + sizeof(EthHeader);
    if (header->caplen < sizeof(EthHeader) + sizeof(IPv4Header))
        return;
    const IPv4Header *ipHdr = reinterpret_cast<const IPv4Header *>(ipStart);
    if (ipHdr->protocol != IP_PROTO_TCP)
        return;

    unsigned ipHeaderLen = (ipHdr->ver_ihl & 0x0F) * 4; // IHL is in 32-bit words
    const uint8_t *tcpStart = ipStart + ipHeaderLen;
    if (header->caplen < (size_t)((tcpStart - packet) + sizeof(TcpHeader)))
        return;
    const TcpHeader *tcpHdr = reinterpret_cast<const TcpHeader *>(tcpStart);

    unsigned tcpHeaderLen = (tcpHdr->data_offset >> 4) * 4; // upper nibble = words
    const uint8_t *payload = tcpStart + tcpHeaderLen;
    size_t totalCaptured = header->caplen;
    size_t headerBytes = (size_t)(payload - packet);
    if (totalCaptured <= headerBytes)
        return; // no payload in this packet
    size_t payloadLen = totalCaptured - headerBytes;

    uint16_t srcPort = ntohs(tcpHdr->src_port);
    uint16_t dstPort = ntohs(tcpHdr->dst_port);

    bool srcMonitored = isMonitoredPort(srcPort);
    bool dstMonitored = isMonitoredPort(dstPort);
    if (!srcMonitored && !dstMonitored)
        return; // 2. Protocol Identification gate

    bool fromClient = dstMonitored; // packet going TOWARDS the mail port = client->server
    uint16_t serverPort = dstMonitored ? dstPort : srcPort;

    FlowKey key;
    if (fromClient)
    {
        key = {ipHdr->src_addr, ipHdr->dst_addr, srcPort, dstPort};
    }
    else
    {
        // normalize key so both directions map to same flow: server->client
        key = {ipHdr->dst_addr, ipHdr->src_addr, dstPort, srcPort};
    }

    std::lock_guard<std::mutex> lk(g_flows_mutex);
    auto it = g_flows.find(key);
    if (it == g_flows.end())
    {
        FlowState fs;
        fs.protocol = identifyProtocol(serverPort);
        fs.implicitTls = (serverPort == 465 || serverPort == 993 || serverPort == 995);
        fs.pendingSni = (serverPort == 443); // classify via SNI before we do anything else
        fs.firstSeen = fs.lastSeen = nowSeconds();
        it = g_flows.emplace(key, fs).first;

        // Port-443 flows aren't announced yet -- we don't know if they're
        // Outlook/Gmail or just regular web browsing until the SNI is read
        // in analyzePayload(). Announcing here would flood the console
        // with every unrelated HTTPS connection on the interface.
        if (!fs.pendingSni)
        {
            std::cout << "[FLOW-NEW] " << fs.protocol << "  "
                      << ipToStr(key.src_ip) << ":" << key.src_port << " <-> "
                      << ipToStr(key.dst_ip) << ":" << key.dst_port << "\n";
        }
    }

    analyzePayload(key, it->second, payload, payloadLen, fromClient);
}

// =====================================================================
// Housekeeping thread: expire stale flows so the map doesn't grow forever
// =====================================================================
static void housekeepingLoop()
{
    using namespace std::chrono_literals;
    while (g_running.load())
    {
        std::this_thread::sleep_for(30s);
        {
            std::lock_guard<std::mutex> lk(g_flows_mutex);
            double cutoff = nowSeconds() - 300.0; // 5 min idle timeout
            for (auto it = g_flows.begin(); it != g_flows.end();)
            {
                if (it->second.lastSeen < cutoff)
                    it = g_flows.erase(it);
                else
                    ++it;
            }
        }

        uint64_t allowed = g_quickAllowCount.exchange(0, std::memory_order_relaxed);
        if (allowed > 0)
        {
            std::cout << "[QUICK-ALLOW] " << allowed
                      << " flow(s) marked Normal in the last 30s\n";
        }
    }
}

static void runSelfTest()
{
    std::cout << "=====================================================\n"
              << " LOCAL C++ ENGINE — SELF TEST\n"
              << "=====================================================\n";
    std::cout << "[SELF-TEST] Simulating STARTTLS acknowledged + no TLS handshake...\n";

    // Documentation-only TEST-NET addresses; no real packet is sent.
    FlowKey key{};
    key.src_ip = inet_addr("192.0.2.10");
    key.dst_ip = inet_addr("198.51.100.25");
    key.src_port = 49876;
    key.dst_port = 587;

    FlowState fs;
    fs.protocol = "SMTP";
    fs.starttlsCommandSeen = true;
    fs.serverAckedStarttls = true;
    fs.tlsHandshakeSeen = false;
    fs.firstSeen = fs.lastSeen = nowSeconds();

    // Use the REAL detector/alert path. This also exercises cloud POST.
    evaluateFlow(key, fs);

    if (fs.alreadyFlagged)
    {
        std::cout << "[SELF-TEST] PASS: local alert decision triggered.\n";
        std::cout << "[SELF-TEST] Reason: STARTTLS stripping suspected\n";
        std::cout << "[SELF-TEST] Check the [CLOUD] line above for backend delivery.\n";
    }
    else
    {
        std::cout << "[SELF-TEST] FAIL: detector did not trigger.\n";
    }
}

static void handleSigint(int)
{
    std::cout << "\n[SHUTDOWN] Stopping real-time engine...\n";
    g_running.store(false);
}

// =====================================================================
// main() — sets up capture (1. Packet Capture) and runs the pipeline
// =====================================================================
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0]
                  << " <interface> [cloud_endpoint_url]\n"
                  << "Example: " << argv[0]
                  << " eth0 https://your-cloud-host/api/events\n";
        return 1;
    }
    std::string iface = argv[1];
    if (argc >= 3)
    {
        g_cloud_endpoint = argv[2];
        const std::string marker = "/api/events";
        auto p = g_cloud_endpoint.rfind(marker);
        if (p != std::string::npos)
            g_heartbeat_endpoint = g_cloud_endpoint.substr(0, p) + "/api/engine/heartbeat";
    }

    std::signal(SIGINT, handleSigint);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "[FATAL] WSAStartup failed\n";
        return 1;
    }
#endif

    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Self-test mode: no Npcap interface is required.
    if (argc >= 2 && (std::string(argv[1]) == "--self-test" ||
                      std::string(argv[1]) == "self-test"))
    {
        runSelfTest();
        curl_global_cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface.c_str(), 65535 /*snaplen*/,
                                    1 /*promisc*/, 1000 /*ms timeout*/, errbuf);
    if (!handle)
    {
        std::cerr << "[FATAL] pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    // BPF filter: only SMTP/IMAP/POP3 (+ their implicit-TLS ports)
    struct bpf_program fp;
    const char *filterExp =
        "tcp port 25 or tcp port 587 or tcp port 465 or "
        "tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995 or "
        "tcp port 443";
    if (pcap_compile(handle, &fp, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "[FATAL] Failed to apply capture filter: "
                  << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return 1;
    }

    std::cout << "=====================================================\n"
              << " LOCAL C++ REAL-TIME ENGINE — Live Traffic Monitoring\n"
              << " Interface     : " << iface << "\n"
              << " Cloud endpoint: " << g_cloud_endpoint << "\n"
              << " Protocols     : SMTP / IMAP / POP3 (+ implicit-TLS ports)\n"
              << "                 + HTTPS(443) mail traffic, classified via\n"
              << "                   TLS SNI -> Outlook 365 / Gmail\n"
              << " NOTE          : port 443 sees ALL HTTPS on this host, not\n"
              << "                 just mail. Non-mail SNI is dropped silently\n"
              << "                 after one ClientHello inspection per flow.\n"
              << "=====================================================\n\n";

    g_capture_interface = iface;
    std::thread housekeeper(housekeepingLoop);
    std::thread heartbeat(engineHeartbeatLoop);

    while (g_running.load())
    {
        int rc = pcap_dispatch(handle, 100, packetHandler, nullptr);
        if (rc == -1)
        {
            std::cerr << "[FATAL] pcap_dispatch error: " << pcap_geterr(handle) << "\n";
            break;
        }
    }

    pcap_freecode(&fp);
    pcap_close(handle);
    curl_global_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    if (housekeeper.joinable())
        housekeeper.join();
    if (heartbeat.joinable())
        heartbeat.join();

    std::cout << "[EXIT] Real-time engine stopped cleanly.\n";
    return 0;
}