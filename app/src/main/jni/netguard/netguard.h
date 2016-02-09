#include <jni.h>

#define TAG "NetGuard.JNI"

#define SELECT_TIMEOUT 600 // seconds

#define TUN_MAXMSG 32768 // bytes (device)
#define ICMP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define ICMP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)
#define UDP4_MAXMSG (IP_MAXPACKET - 20 - 8) // bytes (socket)
#define UDP6_MAXMSG (IPV6_MAXPACKET - 40 - 8) // bytes (socket)

#define ICMP_TIMEOUT 15 // seconds

#define UDP_TIMEOUT_53 15 // seconds
#define UDP_TIMEOUT_ANY 300 // seconds
#define UDP_KEEP_TIMEOUT 60 // seconds
#define UDP_TIMEOUT_SCALE 25

#define TCP_RECV_WINDOW 16384 // bytes (maximum)
#define TCP_SEND_WINDOW 16384 // bytes (maximum)
#define TCP_INIT_TIMEOUT 30 // seconds ~net.inet.tcp.keepinit
#define TCP_IDLE_TIMEOUT 300 // seconds ~net.inet.tcp.keepidle
#define TCP_CLOSE_TIMEOUT 3 // seconds
#define TCP_KEEP_TIMEOUT 300 // seconds
#define TCP_TIMEOUT_SCALE 50
// https://en.wikipedia.org/wiki/Maximum_segment_lifetime

#define UID_DELAY 1 // milliseconds
#define UID_DELAYTRY 10 // milliseconds
#define UID_MAXTRY 3

#define MAX_PCAP_FILE (1024 * 1024) // bytes
#define MAX_PCAP_RECORD 128 // bytes

#define RTLD_NOLOAD 4

struct arguments {
    JNIEnv *env;
    jobject instance;
    int tun;
    jboolean fwd53;
};

struct allowed {
    char raddr[INET6_ADDRSTRLEN + 1];
    uint16_t rport; // host notation
};

struct segment {
    uint32_t seq;
    uint16_t len;
    int psh;
    uint8_t *data;
    struct segment *next;
};

struct icmp_session {
    time_t time;
    jint uid;
    int version;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;

    uint16_t id;

    uint8_t stop;
    jint socket;

    struct icmp_session *next;
};

#define UDP_ACTIVE 0
#define UDP_FINISHING 1
#define UDP_CLOSED 2
#define UDP_BLOCKED 3

struct udp_session {
    time_t time;
    jint uid;
    int version;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;
    __be16 source; // network notation

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;
    __be16 dest; // network notation

    uint8_t state;
    jint socket;

    struct udp_session *next;
};

struct tcp_session {
    jint uid;
    time_t time;
    int version;
    uint16_t recv_window; // host notation
    uint16_t send_window; // host notation

    uint32_t remote_seq; // confirmed bytes received, host notation
    uint32_t local_seq; // confirmed bytes sent, host notation
    uint32_t remote_start;
    uint32_t local_start;

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } saddr;
    __be16 source; // network notation

    union {
        __be32 ip4; // network notation
        struct in6_addr ip6;
    } daddr;
    __be16 dest; // network notation

    uint8_t state;
    jint socket;
    struct segment *forward;

    struct tcp_session *next;
};

// IPv6

struct ip6_hdr_pseudo {
    struct in6_addr ip6ph_src;
    struct in6_addr ip6ph_dst;
    u_int32_t ip6ph_len;
    u_int8_t ip6ph_zero[3];
    u_int8_t ip6ph_nxt;
} __packed;

// PCAP
// https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef uint16_t guint16_t;
typedef uint32_t guint32_t;
typedef int32_t gint32_t;

typedef struct pcap_hdr_s {
    guint32_t magic_number;
    guint16_t version_major;
    guint16_t version_minor;
    gint32_t thiszone;
    guint32_t sigfigs;
    guint32_t snaplen;
    guint32_t network;
} __packed;

typedef struct pcaprec_hdr_s {
    guint32_t ts_sec;
    guint32_t ts_usec;
    guint32_t incl_len;
    guint32_t orig_len;
} __packed;

#define LINKTYPE_RAW 101

// DNS

#define DNS_QCLASS_IN 1
#define DNS_QTYPE_A 1 // IPv4
#define DNS_QTYPE_AAAA 28 // IPv6

#define DNS_QNAME_MAX 63
#define DNS_TTL (10 * 60) // seconds

struct dns_header {
    uint16_t id; // identification number
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd :1; // recursion desired
    uint16_t tc :1; // truncated message
    uint16_t aa :1; // authoritive answer
    uint16_t opcode :4; // purpose of message
    uint16_t qr :1; // query/response flag
    uint16_t rcode :4; // response code
    uint16_t cd :1; // checking disabled
    uint16_t ad :1; // authenticated data
    uint16_t z :1; // its z! reserved
    uint16_t ra :1; // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr :1; // query/response flag
    uint16_t opcode :4; // purpose of message
    uint16_t aa :1; // authoritive answer
    uint16_t tc :1; // truncated message
    uint16_t rd :1; // recursion desired
    uint16_t ra :1; // recursion available
    uint16_t z :1; // its z! reserved
    uint16_t ad :1; // authenticated data
    uint16_t cd :1; // checking disabled
    uint16_t rcode :4; // response code
# else
# error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
} __packed;

typedef struct dns_rr {
    __be16 qname_ptr;
    __be16 qtype;
    __be16 qclass;
    __be32 ttl;
    __be16 rdlength;
} __packed;

// DHCP

#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

typedef struct dhcp_packet {
    uint8_t opcode;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t option_format;
} __packed;

typedef struct dhcp_option {
    uint8_t code;
    uint8_t length;
} __packed;

// Prototypes

void clear_sessions();

void clear_tcp_data(struct tcp_session *cur);

void handle_signal(int sig, siginfo_t *info, void *context);

void *handle_events(void *a);

void report_exit(const struct arguments *args, const char *fmt, ...);

void check_allowed(const struct arguments *args);

void check_sessions(const struct arguments *args, int isessions, int usessions, int tsessions);

int get_select_timeout(int isessions, int usessions, int tsessions);

int get_udp_timeout(const struct udp_session *u, int sessions);

int get_tcp_timeout(const struct tcp_session *t, int sessions);

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void check_icmp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void check_udp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname);

void parse_dns_response(const struct arguments *args, const uint8_t *data, const size_t datalen);

void check_tcp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int is_lower_layer(int protocol);

int is_upper_layer(int protocol);

void handle_ip(const struct arguments *args, const uint8_t *buffer, size_t length);

jboolean handle_icmp(const struct arguments *args,
                     const uint8_t *pkt, size_t length,
                     const uint8_t *payload,
                     int uid);

int has_udp_session(const struct arguments *args, const uint8_t *pkt, const uint8_t *payload);

void block_udp(const struct arguments *args,
               const uint8_t *pkt, size_t length,
               const uint8_t *payload,
               int uid);

jboolean handle_udp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect);

int get_dns_query(const struct arguments *args, const struct udp_session *u,
                  const uint8_t *data, const size_t datalen,
                  uint16_t *qtype, uint16_t *qclass, char *qname);

int check_domain(const struct arguments *args, const struct udp_session *u,
                 const uint8_t *data, const size_t datalen,
                 uint16_t qclass, uint16_t qtype, const char *name);

int check_dhcp(const struct arguments *args, const struct udp_session *u,
               const uint8_t *data, const size_t datalen);

jboolean handle_tcp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect);

void forward_tcp(const struct arguments *args,
                 const struct tcphdr *tcphdr,
                 const char *session, struct tcp_session *cur,
                 const uint8_t *data, uint16_t datalen);

int open_icmp_socket(const struct arguments *args, const struct icmp_session *cur);

int open_udp_socket(const struct arguments *args, const struct udp_session *cur);

int open_tcp_socket(const struct arguments *args,
                    const struct tcp_session *cur, const struct allowed *redirect);

int32_t get_local_port(const int sock);

int write_syn_ack(const struct arguments *args, struct tcp_session *cur);

int write_ack(const struct arguments *args, struct tcp_session *cur, size_t bytes);

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length);

int write_fin_ack(const struct arguments *args, struct tcp_session *cur);

void write_rst(const struct arguments *args, struct tcp_session *cur);

ssize_t write_icmp(const struct arguments *args, const struct icmp_session *cur,
                   uint8_t *data, size_t datalen);

ssize_t write_udp(const struct arguments *args, const struct udp_session *cur,
                  uint8_t *data, size_t datalen);

ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen, size_t confirm,
                  int syn, int ack, int fin, int rst);

uint8_t char2nible(const char c);

void hex2bytes(const char *hex, uint8_t *buffer);

jint get_uid(const int protocol, const int version,
             const void *saddr, const uint16_t sport, int dump);

int protect_socket(const struct arguments *args, int socket);

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length);

jobject jniGlobalRef(JNIEnv *env, jobject cls);

jclass jniFindClass(JNIEnv *env, const char *name);

jmethodID jniGetMethodID(JNIEnv *env, jclass cls, const char *name, const char *signature);

jfieldID jniGetFieldID(JNIEnv *env, jclass cls, const char *name, const char *type);

jobject jniNewObject(JNIEnv *env, jclass cls, jmethodID constructor, const char *name);

int jniCheckException(JNIEnv *env);

int sdk_int(JNIEnv *env);

int __system_property_get(JNIEnv *env, const char *name, char *value);

void log_android(int prio, const char *fmt, ...);

void log_packet(const struct arguments *args, jobject jpacket);

void dns_resolved(const struct arguments *args,
                  const char *qname, const char *aname, const char *resource, int ttl);

jboolean is_domain_blocked(const struct arguments *args, const char *name);

struct allowed *is_address_allowed(const struct arguments *args, jobject objPacket);

jobject create_packet(const struct arguments *args,
                      jint version,
                      jint protocol,
                      const char *flags,
                      const char *source,
                      jint sport,
                      const char *dest,
                      jint dport,
                      const char *data,
                      jint uid,
                      jboolean allowed);

void write_pcap_hdr();

void write_pcap_rec(const uint8_t *buffer, size_t len);

void write_pcap(const void *ptr, size_t len);

int compare_u16(uint32_t seq1, uint32_t seq2);

const char *strstate(const int state);

char *hex(const u_int8_t *data, const size_t len);
