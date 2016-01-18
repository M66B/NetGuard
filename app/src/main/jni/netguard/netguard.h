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

void handle_events(void *);

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds);

int check_tun(const struct arguments *, fd_set *, fd_set *, fd_set *);

void check_sockets(const struct arguments *, fd_set *, fd_set *, fd_set *);

void handle_ip(const struct arguments *, const uint8_t *, const uint16_t);

void handle_tcp(const struct arguments *, const uint8_t *, const uint16_t, int uid);

int open_socket(const struct arguments *, const struct sockaddr_in *);

int get_local_port(const int);

int write_tcp(const struct session *, uint8_t *, uint16_t, uint16_t, int, int, int, int);

jint get_uid(const int, const int, const void *, const uint16_t);

uint16_t checksum(uint8_t *, uint16_t);

void ng_log(int, const char *, ...);

const char *strstate(const int state);

char *hex(const u_int8_t *, const u_int16_t);

void pcap_write(const void *, size_t);
