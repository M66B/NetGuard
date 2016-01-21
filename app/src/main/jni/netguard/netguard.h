#include <jni.h>

#define TAG "NetGuard.JNI"
#define MAX_PKTSIZE 32768
#define MAX_DATASIZE4 (MAX_PKTSIZE-60-60) // IP/TCP header
#define SELECT_TIMEOUT 10 // seconds
#define UDP_TIMEOUT 300 // seconds
#define UDP_TTL 64
#define TCP_INIT_TIMEOUT 30 // seconds ~net.inet.tcp.keepinit
#define TCP_IDLE_TIMEOUT 300 // seconds ~net.inet.tcp.keepidle
#define TCP_CLOSE_TIMEOUT 30
#define TCP_TTL 64
#define TCP_WINDOW 32768
#define UID_DELAY 1 // milliseconds
#define UID_DELAYTRY 10 // milliseconds
#define UID_MAXTRY 3
#define MAX_PCAP 80

struct arguments {
    JNIEnv *env;
    jobject instance;
    int tun;
    jint count;
    jint *uid;
    jboolean log;
    jboolean filter;
};

struct udp_session {
    // TODO UDPv6
    time_t time;
    jint uid;
    int version;
    int32_t saddr; // network notation
    __be16 source; // network notation
    int32_t daddr; // network notation
    __be16 dest; // network notation
    jint socket;
    struct udp_session *next;
};

struct tcp_session {
    // TODO TCPv6
    time_t time;
    jint uid;
    int version;
    uint32_t remote_seq; // confirmed bytes received, host notation
    uint32_t local_seq; // confirmed bytes sent, host notation
    uint32_t remote_start;
    uint32_t local_start;
    int32_t saddr; // network notation
    __be16 source; // network notation
    int32_t daddr; // network notation
    __be16 dest; // network notation
    uint8_t state;
    jint socket;
    struct tcp_session *next;
};

// https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef unsigned short guint16_t;
typedef unsigned int guint32_t;
typedef signed int gint32_t;

typedef struct pcap_hdr_s {
    guint32_t magic_number;
    guint16_t version_major;
    guint16_t version_minor;
    gint32_t thiszone;
    guint32_t sigfigs;
    guint32_t snaplen;
    guint32_t network;
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
    guint32_t ts_sec;
    guint32_t ts_usec;
    guint32_t incl_len;
    guint32_t orig_len;
} pcaprec_hdr_t;

#define LINKTYPE_RAW 101

void clear_sessions();

void handle_signal(int sig, siginfo_t *info, void *context);

void handle_events(void *a);

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void check_udp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void check_tcp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void handle_ip(const struct arguments *args, const uint8_t *buffer, const uint16_t length);

jboolean handle_udp(const struct arguments *args, const uint8_t *buffer, uint16_t length, int uid);

jboolean handle_tcp(const struct arguments *args, const uint8_t *buffer, uint16_t length, int uid);

int open_tcp(const struct tcp_session *cur, const struct arguments *args);

uint16_t get_local_port(const int sock);

ssize_t send_socket(int sock, uint8_t *buffer, uint16_t len);

int write_syn_ack(const struct arguments *args, struct tcp_session *cur, int tun);

int write_ack(const struct arguments *args, struct tcp_session *cur, int bytes, int tun);

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, uint16_t length, int tun);

int write_fin_ack(const struct arguments *args, struct tcp_session *cur, int bytes, int tun);

int write_fin(const struct arguments *args, struct tcp_session *cur, int tun);

void write_rst(const struct arguments *args, struct tcp_session *cur, int tun);

int write_udp(const struct arguments *args, const struct udp_session *cur,
              uint8_t *data, uint16_t datalen, int tun);

int write_tcp(const struct arguments *args, const struct tcp_session *cur,
              uint8_t *data, uint16_t datalen, uint16_t confirm,
              int syn, int ack, int fin, int rst, int tun);

jint get_uid(const int protocol, const int version,
             const void *saddr, const uint16_t sport, int dump);

uint16_t calc_checksum(uint8_t *buffer, uint16_t length);

void log_android(int prio, const char *fmt, ...);

void log_packet(const struct arguments *args,
                jlong time,
                jint version,
                const char *dest,
                jint protocol,
                jint dport,
                const char *flags,
                jint uid,
                jboolean allowed);

void write_pcap(const void *ptr, size_t len);

void write_pcap_hdr();

void write_pcap_rec(const uint8_t *buffer, uint16_t len);

const char *strstate(const int state);

char *hex(const u_int8_t *data, const u_int16_t len);
