#include <jni.h>

#define TAG "NetGuard.JNI"
#define MAXPKT 32768
// TODO TCP parameters (net.inet.tcp.keepinit, etc)
#define SELECTWAIT 10 // seconds
#define TCPTIMEOUT 300 // seconds ~net.inet.tcp.keepidle
#define TCPTTL 64
#define TCPWINDOW 32768
#define UIDDELAY 100 // milliseconds
#define UIDTRIES 10
#define MAXPCAP 80

struct arguments {
    JNIEnv *env;
    jobject instance;
    int tun;
};

struct session {
    time_t time;
    int uid;
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
    uint32_t lport; // host notation
    struct session *next;
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

void handle_signal(int sig, siginfo_t *info, void *context);

void handle_events(void *a);

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void check_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

void handle_ip(const struct arguments *args, const uint8_t *buffer, const uint16_t length);

void handle_tcp(const struct arguments *args, const uint8_t *buffer, uint16_t length, int uid);

int open_socket(const struct session *cur, const struct arguments *args);

int get_local_port(const int sock);

ssize_t send_socket(int sock, uint8_t *buffer, uint16_t len);

int write_syn_ack(struct session *cur, int tun);

int write_ack(struct session *cur, int bytes, int tun);

int write_data(struct session *cur, const uint8_t *buffer, uint16_t length, int tun);

int write_fin(struct session *cur, int tun);

void write_rst(struct session *cur, int tun);

int write_tcp(const struct session *cur,
              uint8_t *data, uint16_t datalen, uint16_t confirm,
              int syn, int fin, int rst, int tun);

jint get_uid(const int protocol, const int version, const void *saddr, const uint16_t sport);

uint16_t calc_checksum(uint8_t *buffer, uint16_t length);

void log_android(int prio, const char *fmt, ...);

void log_java(const struct arguments *args, uint8_t version,
              const char *source, uint16_t sport,
              const char *dest, uint16_t dport,
              uint8_t protocol, const char *flags,
              jint uid, jboolean allowed);

void write_pcap(const void *ptr, size_t len);

const char *strstate(const int state);

char *hex(const u_int8_t *data, const u_int16_t len);
