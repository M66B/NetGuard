#include <jni.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

// TODO TCP fragmentation
// TODO TCP push
// TODO TCPv6
// TODO UDPv4
// TODO UDPv6
// TODO DHCP
// TODO log allowed traffic
// TODO header file
// TODO fix warnings

// Window size < 2^31: x <= y: (uint32_t)(y-x) < 0x80000000

// It is assumed that no packets will get lost and that packets arrive in order

#define TAG "NetGuard.JNI"
#define MAXPKT 32768
// TODO TCP parameters (net.inet.tcp.keepinit, etc)
#define SELECTWAIT 10 // seconds
#define TCPTIMEOUT 300 // seconds ~net.inet.tcp.keepidle
#define TCPTTL 64
#define TCPWINDOW 32768
#define UIDDELAY 10 // milliseconds
#define MAXPCAP 80

struct arguments {
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

void pcap_write(const void *, size_t);

void *handle_events(void *);

void handle_ip(JNIEnv *, jobject, const struct arguments *, const uint8_t *, const uint16_t);

void handle_tcp(JNIEnv *, jobject, const struct arguments *args,
                const uint8_t *, const uint16_t, int uid);

int openSocket(JNIEnv *, jobject, const struct sockaddr_in *);

int getLocalPort(const int);

int writeTCP(const struct session *, uint8_t *, uint16_t, uint16_t, int, int, int, int);

jint getUid(const int, const int, const void *, const uint16_t);

uint16_t checksum(uint8_t *, uint16_t);

void ng_log(int, const char *, ...);

const char *strstate(const int state);

char *hex(const u_int8_t *, const u_int16_t);

// Global variables

static JavaVM *jvm;
pthread_t thread_id;
int signaled = 0;
struct session *session = NULL;
int loglevel = ANDROID_LOG_WARN;
char *pcap_fn = NULL;

// JNI

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance,
                                                    jint loglevel_, jstring pcap_) {
    loglevel = loglevel_;
    const char *pcap = (*env)->GetStringUTFChars(env, pcap_, 0);

    if (pcap == NULL)
        pcap_fn = NULL;
    else {
        pcap_fn = malloc(strlen(pcap) + 1);
        strcpy(pcap_fn, pcap);

        ng_log(ANDROID_LOG_INFO, "PCAP %s", pcap_fn);

        session = NULL;
        struct pcap_hdr_s pcap_hdr;
        pcap_hdr.magic_number = 0xa1b2c3d4;
        pcap_hdr.version_major = 2;
        pcap_hdr.version_minor = 4;
        pcap_hdr.thiszone = 0;
        pcap_hdr.sigfigs = 0;
        pcap_hdr.snaplen = MAXPCAP;
        pcap_hdr.network = LINKTYPE_RAW;
        pcap_write(&pcap_hdr, sizeof(struct pcap_hdr_s));
    }

    (*env)->ReleaseStringUTFChars(env, pcap_, pcap);
}

void pcap_write(const void *ptr, size_t len) {
    FILE *fd = fopen(pcap_fn, "ab");
    if (fd == NULL)
        ng_log(ANDROID_LOG_ERROR, "fopen %s error %d: %s",
               pcap_fn, errno, strerror(errno));
    else {
        if (fwrite(ptr, len, 1, fd) < 1)
            ng_log(ANDROID_LOG_ERROR, "fwrite %s error %d: %s",
                   pcap_fn, errno, strerror(errno));
        else
            ng_log(ANDROID_LOG_DEBUG, "PCAP write %d", len);

        if (fclose(fd))
            ng_log(ANDROID_LOG_ERROR, "fclose %s error %d: %s",
                   pcap_fn, errno, strerror(errno));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1start(JNIEnv *env, jobject instance,
                                                     jint tun) {
    ng_log(ANDROID_LOG_INFO, "Starting tun=%d", tun);

    if (pthread_kill(thread_id, 0) == 0)
        ng_log(ANDROID_LOG_WARN, "Already running thread %u", thread_id);
    else {
        jint rs = (*env)->GetJavaVM(env, &jvm);
        if (rs != JNI_OK)
            ng_log(ANDROID_LOG_ERROR, "GetJavaVM failed");

        struct arguments *args = malloc(sizeof(struct arguments));
        args->instance = (*env)->NewGlobalRef(env, instance);
        args->tun = tun;
        int err = pthread_create(&thread_id, NULL, handle_events, args);
        if (err == 0)
            ng_log(ANDROID_LOG_INFO, "Started thread %u", thread_id);
        else
            ng_log(ANDROID_LOG_ERROR, "pthread_create error %d: %s",
                   err, strerror(err));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1stop(JNIEnv *env, jobject instance,
                                                    jint tun, jboolean clear) {
    ng_log(ANDROID_LOG_INFO, "Stop tun %d clear %d", tun, clear);
    if (pthread_kill(thread_id, 0) == 0) {
        ng_log(ANDROID_LOG_DEBUG, "Kill thread %u", thread_id);
        int err = pthread_kill(thread_id, SIGUSR1);
        if (err != 0)
            ng_log(ANDROID_LOG_WARN, "pthread_kill error %d: %s",
                   err, strerror(err));
        else {
            ng_log(ANDROID_LOG_DEBUG, "Join thread %u", thread_id);
            pthread_join(thread_id, NULL);
            if (err != 0)
                ng_log(ANDROID_LOG_WARN, "pthread_join error %d: %s",
                       err, strerror(err));
        }
        if (clear) {
            struct session *s = session;
            while (s != NULL) {
                struct session *p = s;
                s = s->next;
                free(p);
            }
            session = NULL;
        }
        ng_log(ANDROID_LOG_INFO, "Stopped thread %u", thread_id);
    } else
        ng_log(ANDROID_LOG_WARN, "Not running");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1done(JNIEnv *env, jobject instance) {
    ng_log(ANDROID_LOG_INFO, "Done");
    free(pcap_fn);
}

// Private functions

void sig_handler(int sig, siginfo_t *info, void *context) {
    ng_log(ANDROID_LOG_DEBUG, "Signal %d", sig);
    signaled = 1;
}

void *handle_events(void *a) {
    struct arguments *args = (struct arguments *) a;
    ng_log(ANDROID_LOG_INFO, "Start events tun=%d thread %u", args->tun,
           thread_id);

    JNIEnv *env;
    jint rs = (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    if (rs != JNI_OK)
        ng_log(ANDROID_LOG_ERROR, "AttachCurrentThread failed");

    int max;
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    struct timespec ts;
    char dest[20];
    sigset_t blockset;
    sigset_t emptyset;
    struct sigaction sa;

    // Block SIGUSR1
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blockset, NULL);

    /// Handle SIGUSR1
    sa.sa_sigaction = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    signaled = 0;

    // Loop
    while (1) {
        time_t now = time(NULL);
        ng_log(ANDROID_LOG_DEBUG, "Loop thread %u", thread_id);

        // Select
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);

        // Always read tun
        FD_SET(args->tun, &rfds);
        FD_SET(args->tun, &efds);

        max = args->tun;

        struct session *last = NULL;
        struct session *cur = session;
        while (cur != NULL) {
            // TODO differentiate timeouts
            if (cur->time + TCPTIMEOUT < now) {
                // TODO send keep alives?
                ng_log(ANDROID_LOG_WARN, "Idle lport %u",
                       cur->lport);
                if (cur->state == TCP_SYN_RECV ||
                    cur->state == TCP_ESTABLISHED ||
                    cur->state == TCP_CLOSE_WAIT) {
                    if (writeTCP(cur, NULL, 0, 0, 0, 1, 0, args->tun) < 0) { // FIN
                        ng_log(ANDROID_LOG_ERROR,
                               "write FIN lport %u error %d: %s",
                               cur->lport, errno, strerror((errno)));
                        cur->state = TCP_TIME_WAIT; // Will close socket
                    }
                    else {
                        ng_log(ANDROID_LOG_DEBUG,
                               "Half close initiated");
                        cur->local_seq++;
                        if (cur->state == TCP_SYN_RECV || cur->state == TCP_ESTABLISHED)
                            cur->state = TCP_FIN_WAIT1;
                        else // close wait
                            cur->state = TCP_LAST_ACK;
                    }

                } else
                    cur->state = TCP_TIME_WAIT; // Will close socket
            }

            if (cur->state == TCP_TIME_WAIT) {
                // Log
                ng_log(ANDROID_LOG_DEBUG, "Close lport %u",
                       cur->lport);

                // TODO keep for some time

                // TODO non blocking?
                if (close(cur->socket))
                    ng_log(ANDROID_LOG_ERROR, "close error %d: %s",
                           errno, strerror(errno));

                if (last == NULL)
                    session = cur->next;
                else
                    last->next = cur->next;

                struct session *c = cur;
                cur = cur->next;
                free(c);
                continue;

            } else if (cur->state != TCP_TIME_WAIT) {
                if (cur->state == TCP_LISTEN) {
                    FD_SET(cur->socket, &efds);
                    FD_SET(cur->socket, &wfds);
                    if (cur->socket > max)
                        max = cur->socket;
                }
                else if (cur->state == TCP_ESTABLISHED ||
                         cur->state == TCP_SYN_RECV ||
                         cur->state == TCP_CLOSE_WAIT) {
                    FD_SET(cur->socket, &efds);
                    FD_SET(cur->socket, &rfds);
                    if (cur->socket > max)
                        max = cur->socket;
                }
            }

            last = cur;
            cur = cur->next;
        }

        ts.tv_sec = SELECTWAIT;
        ts.tv_nsec = 0;
        // TODO let timeout depend on session timeouts
        sigemptyset(&emptyset);
        int ready = pselect(max + 1, &rfds, &wfds, &efds, session == NULL ? NULL : &ts, &emptyset);
        if (ready < 0) {
            if (errno == EINTR) {
                if (signaled) { ;
                    ng_log(ANDROID_LOG_DEBUG, "pselect signaled");
                    break;
                } else {
                    ng_log(ANDROID_LOG_WARN, "pselect interrupted");
                    continue;
                }
            } else {
                ng_log(ANDROID_LOG_ERROR, "pselect error %d: %s",
                       errno, strerror(errno));
                break;
            }
        }

        int sessions = 0;
        struct session *s = session;
        while (s != NULL) {
            sessions++;
            s = s->next;
        }

        if (ready == 0)
            ng_log(ANDROID_LOG_DEBUG, "pselect timeout sessions %d", sessions);
        else {
            ng_log(ANDROID_LOG_DEBUG, "pselect sessions %d ready %d",
                   sessions, ready);

            // Check tun exception
            if (FD_ISSET(args->tun, &efds)) {
                ng_log(ANDROID_LOG_ERROR, "tun exception");
                break;
            }

            // Check tun read
            if (FD_ISSET(args->tun, &rfds)) {
                uint8_t buffer[MAXPKT];
                ssize_t length = read(args->tun, buffer, MAXPKT);
                if (length < 0) {
                    ng_log(ANDROID_LOG_ERROR, "tun read error %d: %s",
                           errno, strerror(errno));
                    if (errno == EINTR)
                        continue;
                    else
                        break;
                }
                else if (length > 0) {
                    if (pcap_fn != NULL) {
                        struct timespec ts;
                        if (clock_gettime(CLOCK_REALTIME, &ts))
                            ng_log(ANDROID_LOG_ERROR,
                                   "clock_gettime error %d: %s",
                                   errno, strerror(errno));


                        int plen = (length < MAXPCAP ? length : MAXPCAP);
                        struct pcaprec_hdr_s *pcap_rec = malloc(
                                sizeof(struct pcaprec_hdr_s) + plen);

                        pcap_rec->ts_sec = ts.tv_sec;
                        pcap_rec->ts_usec = ts.tv_nsec / 1000;
                        pcap_rec->incl_len = plen;
                        pcap_rec->orig_len = length;
                        memcpy(((uint8_t *) pcap_rec) + sizeof(struct pcaprec_hdr_s), buffer, plen);

                        pcap_write(pcap_rec, sizeof(struct pcaprec_hdr_s) + plen);

                        free(pcap_rec);
                    }

                    handle_ip(env, args->instance, args, buffer, length);
                }
                else {
                    ng_log(ANDROID_LOG_ERROR, "tun empty read");
                    break;
                }
            }

            // Check sockets
            struct session *cur = session;
            while (cur != NULL) {
                if (FD_ISSET(cur->socket, &efds)) {
                    // Socket exception
                    int serr;
                    socklen_t optlen = sizeof(int);
                    int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
                    if (err < 0)
                        ng_log(ANDROID_LOG_ERROR,
                               "getsockopt lport %u error %d: %s",
                               cur->lport, errno, strerror(errno));
                    if (err < 0 || serr) {
                        ng_log(ANDROID_LOG_ERROR, "lport %u SO_ERROR %d: %s",
                               cur->lport, serr, strerror(serr));
                        if (err < 0 || (serr && serr != EINTR)) {
                            if (writeTCP(cur, NULL, 0, 0, 0, 0, 1, args->tun) < 0) // RST
                                ng_log(ANDROID_LOG_ERROR,
                                       "write RST error %d: %s",
                                       errno, strerror((errno)));
                        }
                    }
                }
                else {
                    // Assume socket okay
                    if (cur->state == TCP_LISTEN) {
                        // Check socket connect
                        if (FD_ISSET(cur->socket, &wfds)) {
                            // Log
                            char dest[20];
                            inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
                            ng_log(ANDROID_LOG_DEBUG, "Connected lport %u %s/%u",
                                   cur->lport, dest, ntohs(cur->dest));

                            if (writeTCP(cur, NULL, 0, 1, 1, 0, 0, args->tun) < 0) { // SYN+ACK
                                ng_log(ANDROID_LOG_ERROR,
                                       "write SYN+ACK error %d: %s",
                                       errno, strerror((errno)));
                                // Remote will retry
                                cur->state = TCP_TIME_WAIT; // will close socket
                                cur = cur->next;
                                continue;
                            } else {
                                cur->local_seq++; // local SYN
                                cur->remote_seq++; // remote SYN
                                cur->state = TCP_SYN_RECV;
                            }
                        }
                    }

                    else if (cur->state == TCP_SYN_RECV ||
                             cur->state == TCP_ESTABLISHED ||
                             cur->state == TCP_CLOSE_WAIT) {
                        // Check socket read
                        if (FD_ISSET(cur->socket, &rfds)) {
                            // TODO window size
                            uint8_t buffer[MAXPKT];
                            ssize_t bytes = recv(cur->socket, buffer, MAXPKT, 0);
                            if (bytes < 0) {
                                // Socket error
                                ng_log(ANDROID_LOG_ERROR,
                                       "recv lport %u error %d: %s",
                                       cur->lport, errno, strerror(errno));
                                if (errno != EINTR) {
                                    if (writeTCP(cur, NULL, 0, 0, 0, 0, 1, args->tun) < 0) // RST
                                        ng_log(ANDROID_LOG_ERROR,
                                               "write RST error %d: %s",
                                               errno, strerror((errno)));
                                }
                            }
                            else if (bytes == 0) {
                                // Socket peer closed
                                ng_log(ANDROID_LOG_DEBUG,
                                       "recv empty lport %u state %s",
                                       cur->lport, strstate(cur->state));

                                if (writeTCP(cur, NULL, 0, 0, 0, 1, 0, args->tun) < 0) // FIN
                                    ng_log(ANDROID_LOG_ERROR,
                                           "write FIN lport %u error %d: %s",
                                           cur->lport, errno, strerror((errno)));
                                else {
                                    cur->local_seq++; // local FIN
                                    if (cur->state == TCP_SYN_RECV || cur->state == TCP_ESTABLISHED)
                                        cur->state = TCP_FIN_WAIT1;
                                    else // close wait
                                        cur->state = TCP_LAST_ACK;
                                    ng_log(ANDROID_LOG_DEBUG, "Half close state %s",
                                           strstate(cur->state));
                                }
                            } else {
                                // Socket read
                                ng_log(ANDROID_LOG_DEBUG,
                                       "recv lport %u bytes %d state %s",
                                       cur->lport, bytes, strstate(cur->state));
                                if (writeTCP(cur, buffer, bytes, 0, 0, 0, 0, args->tun) < 0) // ACK
                                    ng_log(ANDROID_LOG_ERROR,
                                           "write ACK lport %u error %d: %s",
                                           cur->lport, errno, strerror((errno)));
                                else
                                    cur->local_seq += bytes; // received from socket
                            }
                        }
                    }
                }

                cur = cur->next;
            }
        }
    }

    (*env)->DeleteGlobalRef(env, args->instance);
    rs = (*jvm)->DetachCurrentThread(jvm);
    if (rs != JNI_OK)
        ng_log(ANDROID_LOG_ERROR, "DetachCurrentThread failed");
    free(args);

    ng_log(ANDROID_LOG_INFO, "Stopped events tun=%d thread %u",
           args->tun, thread_id);
    // TODO conditionally report to Java
}

void handle_ip(JNIEnv *env, jobject instance, const struct arguments *args,
               const uint8_t *buffer, const uint16_t length) {
    uint8_t protocol;
    void *saddr;
    void *daddr;
    char source[40];
    char dest[40];
    char flags[10];
    int flen = 0;
    uint8_t *payload;

    // Get protocol, addresses & payload
    uint8_t version = (*buffer) >> 4;
    if (version == 4) {
        struct iphdr *ip4hdr = buffer;

        protocol = ip4hdr->protocol;
        saddr = &ip4hdr->saddr;
        daddr = &ip4hdr->daddr;

        if (ip4hdr->frag_off & IP_MF)
            flags[flen++] = '+';

        uint8_t optlen = (ip4hdr->ihl - 5) * 4;
        payload = buffer + 20 + optlen;

        if (ntohs(ip4hdr->tot_len) != length) {
            ng_log(ANDROID_LOG_ERROR, "Invalid length %u header length %u",
                   length, ntohs(ip4hdr->tot_len));
            return;
        }

        uint16_t csum = checksum(ip4hdr, sizeof(struct iphdr));
        if (csum != 0) {
            ng_log(ANDROID_LOG_ERROR, "Invalid IP checksum");
            return;
        }
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = buffer;

        protocol = ip6hdr->ip6_nxt;
        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;

        payload = buffer + 40;

        // TODO check length
        // TODO checksum
    }
    else {
        ng_log(ANDROID_LOG_WARN, "Unknown version %d", version);
        return;
    }

    inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));

    // Get ports & flags
    int syn = 0;
    uint16_t sport = -1;
    uint16_t dport = -1;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = payload;

        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);

        if (tcp->syn) {
            syn = 1;
            flags[flen++] = 'S';
        }
        if (tcp->ack)
            flags[flen++] = 'A';
        if (tcp->psh)
            flags[flen++] = 'P';
        if (tcp->fin)
            flags[flen++] = 'F';
        if (tcp->rst)
            flags[flen++] = 'R';

        // TODO checksum
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = payload;

        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);

        // TODO checksum
    }
    flags[flen] = 0;

    // Get uid
    jint uid = -1;
    if ((protocol == IPPROTO_TCP && syn) || protocol == IPPROTO_UDP) {
        // Sleep 10 ms
        // TODO uid retry
        usleep(1000 * UIDDELAY);

        // Lookup uid
        uid = getUid(protocol, version, saddr, sport);
        if (uid < 0 && version == 4) {
            int8_t saddr128[16];
            memset(saddr128, 0, 10);
            saddr128[10] = 0xFF;
            saddr128[11] = 0xFF;
            memcpy(saddr128 + 12, saddr, 4);
            uid = getUid(protocol, 6, saddr128, sport);
        }
    }

    ng_log(ANDROID_LOG_DEBUG,
           "Packet v%d %s/%u -> %s/%u proto %d flags %s uid %d",
           version, source, sport, dest, dport, protocol, flags, uid);

    if (protocol == IPPROTO_TCP)
        handle_tcp(env, instance, args, buffer, length, uid);

    // Call back
    if ((protocol == IPPROTO_TCP && syn) || protocol == IPPROTO_UDP) {
        jclass cls = (*env)->GetObjectClass(env, instance);
        jmethodID mid = (*env)->GetMethodID(env, cls, "logPacket",
                                            "(ILjava/lang/String;ILjava/lang/String;IILjava/lang/String;IZ)V");
        if (mid == 0)
            ng_log(ANDROID_LOG_ERROR, "logPacket not found");
        else {
            jboolean allowed = 0;
            jstring jsource = (*env)->NewStringUTF(env, source);
            jstring jdest = (*env)->NewStringUTF(env, dest);
            jstring jflags = (*env)->NewStringUTF(env, flags);
            (*env)->CallVoidMethod(env, instance, mid,
                                   version,
                                   jsource, sport,
                                   jdest, dport,
                                   protocol, jflags,
                                   uid, allowed);
            (*env)->DeleteLocalRef(env, jsource);
            (*env)->DeleteLocalRef(env, jdest);
            (*env)->DeleteLocalRef(env, jflags);

            jthrowable ex = (*env)->ExceptionOccurred(env);
            if (ex) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                (*env)->DeleteLocalRef(env, ex);
            }
        }
        (*env)->DeleteLocalRef(env, cls);
    }
}

void handle_tcp(JNIEnv *env, jobject instance, const struct arguments *args,
                const uint8_t *buffer, uint16_t length, int uid) {
    // Check version
    uint8_t version = (*buffer) >> 4;
    if (version != 4)
        return;

    // Get headers
    struct iphdr *iphdr = buffer;
    uint8_t optlen = (iphdr->ihl - 5) * 4;
    struct tcphdr *tcphdr = buffer + sizeof(struct iphdr) + optlen;
    if (optlen)
        ng_log(ANDROID_LOG_INFO, "optlen %d", optlen);

    // Get data
    uint16_t dataoff = sizeof(struct iphdr) + optlen + sizeof(struct tcphdr);
    uint16_t datalen = length - dataoff;

    // Search session
    struct session *last = NULL;
    struct session *cur = session;
    while (cur != NULL && !(cur->saddr == iphdr->saddr && cur->source == tcphdr->source &&
                            cur->daddr == iphdr->daddr && cur->dest == tcphdr->dest)) {
        last = cur;
        cur = cur->next;
    }

    // Log
    char dest[20];
    inet_ntop(AF_INET, &(iphdr->daddr), dest, sizeof(dest));
    ng_log(ANDROID_LOG_DEBUG, "Received %s/%u seq %u ack %u window %u data %d",
           dest, ntohs(tcphdr->dest),
           ntohl(tcphdr->seq) - (cur == NULL ? 0 : cur->remote_start),
           ntohl(tcphdr->ack_seq) - (cur == NULL ? 0 : cur->local_start),
           ntohs(tcphdr->window), datalen);

    if (cur == NULL) {
        if (tcphdr->syn) {
            ng_log(ANDROID_LOG_DEBUG, "New SYN");

            // Register session
            struct session *syn = malloc(sizeof(struct session));
            syn->time = time(NULL);
            syn->uid = uid;
            syn->remote_seq = ntohl(tcphdr->seq); // ISN remote
            syn->local_seq = rand(); // ISN local
            syn->remote_start = syn->remote_seq;
            syn->local_start = syn->local_seq;
            syn->saddr = iphdr->saddr;
            syn->source = tcphdr->source;
            syn->daddr = iphdr->daddr;
            syn->dest = tcphdr->dest;
            syn->state = TCP_LISTEN;
            syn->next = NULL;

            // TODO handle SYN data?

            // Build target address
            struct sockaddr_in daddr;
            memset(&daddr, 0, sizeof(struct sockaddr_in));
            daddr.sin_family = AF_INET;
            daddr.sin_port = tcphdr->dest;
            daddr.sin_addr.s_addr = iphdr->daddr;

            // Open socket
            syn->socket = openSocket(env, instance, &daddr);
            if (syn->socket < 0) {
                syn->state = TCP_TIME_WAIT;
                // Remote will retry
                free(syn);
            }
            else {
                syn->lport = getLocalPort(syn->socket);

                ng_log(ANDROID_LOG_DEBUG, "Connecting to %s/%u lport %u",
                       dest, ntohs(tcphdr->dest), syn->lport);
                if (last == NULL)
                    session = syn;
                else
                    last->next = syn;
            }
        }
        else {
            ng_log(ANDROID_LOG_WARN, "Unknown session");
            struct session rst;
            memset(&rst, 0, sizeof(struct session));
            rst.saddr = iphdr->saddr;
            rst.source = tcphdr->source;
            rst.daddr = iphdr->daddr;
            rst.dest = tcphdr->dest;

            if (writeTCP(&rst, NULL, 0, 0, 0, 0, 1, args->tun) < 0)
                ng_log(ANDROID_LOG_ERROR,
                       "write RST error %d: %s",
                       errno, strerror((errno)));
        }
    }
    else {
        int oldstate = cur->state;
        uint32_t oldlocal = cur->local_seq;
        uint32_t oldremote = cur->remote_seq;

        ng_log(ANDROID_LOG_DEBUG,
               "Session lport %u state %s local %u remote %u",
               cur->lport, strstate(cur->state),
               cur->local_seq - cur->local_start,
               cur->remote_seq - cur->remote_start);

        // Do not change order of conditions

        if (tcphdr->rst) {
            cur->time = time(NULL);
            cur->state = TCP_TIME_WAIT; // will close socket
        }

        else if (tcphdr->syn)
            ng_log(ANDROID_LOG_DEBUG, "Ignoring repeated SYN");

        else if (tcphdr->fin /* ACK */) {
            if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                ntohl(tcphdr->seq) == cur->remote_seq) {
                cur->time = time(NULL);

                ng_log(ANDROID_LOG_DEBUG, "socket RD shutdown");
                if (shutdown(cur->socket, SHUT_RD)) {
                    ng_log(ANDROID_LOG_ERROR, "shutdown RD error %d: %s",
                           errno, strerror(errno));
                    // Socket could be closed by remote
                }

                int ok = 1;
                if (tcphdr->ack && datalen) {
                    ng_log(ANDROID_LOG_DEBUG, "send socket data %u",
                           datalen);
                    // TODO non blocking
                    if (send(cur->socket, buffer + dataoff, datalen, 0) < 0) {
                        ng_log(ANDROID_LOG_ERROR, "send error %d: %s",
                               errno, strerror(errno));
                        ok = 0;
                    }
                    else {
                        if (shutdown(cur->socket, SHUT_WR)) {
                            ng_log(ANDROID_LOG_ERROR,
                                   "shutdown WR error %d: %s",
                                   errno, strerror(errno));
                            ok = 0;
                            // Data might be lost
                        }
                        else
                            ng_log(ANDROID_LOG_DEBUG, "socket WR shutdown");
                    }
                }

                if (ok) {
                    if (writeTCP(cur, NULL, 0, 1 + datalen, 0, 0, 0, args->tun) < 0) // ACK
                        ng_log(ANDROID_LOG_ERROR,
                               "write ACK error %d: %s",
                               errno, strerror((errno)));
                    else {
                        cur->remote_seq += (1 + datalen); // FIN + received from tun
                        if (cur->state == TCP_ESTABLISHED /* && !tcphdr->ack */)
                            cur->state = TCP_CLOSE_WAIT;
                        else if (cur->state == TCP_FIN_WAIT1 && tcphdr->ack)
                            cur->state = TCP_TIME_WAIT;
                        else if (cur->state == TCP_FIN_WAIT1 && !tcphdr->ack)
                            cur->state = TCP_CLOSING;
                        else if (cur->state == TCP_FIN_WAIT2 /* && !tcphdr->ack */)
                            cur->state = TCP_TIME_WAIT;
                        else
                            ng_log(ANDROID_LOG_ERROR, "Invalid FIN state %s ACK %d",
                                   strstate(cur->state), tcphdr->ack);
                    }
                }
            }
            else {
                // TODO proper wrap around
                if (cur->state == TCP_FIN_WAIT1 &&
                    ntohl(tcphdr->seq) == cur->remote_seq &&
                    ntohl(tcphdr->ack_seq) < cur->local_seq) {
                    int confirm = cur->local_seq - ntohl(tcphdr->ack_seq);
                    ng_log(ANDROID_LOG_INFO, "Simultaneous close %d", confirm);

                    if (writeTCP(cur, NULL, 0, confirm, 0, 0, 0, args->tun) < 0) // ACK
                        ng_log(ANDROID_LOG_ERROR,
                               "write ACK error %d: %s",
                               errno, strerror((errno)));
                }
                else
                    ng_log(ANDROID_LOG_WARN, "Invalid FIN seq %u/%u ack %u/%u",
                           ntohl(tcphdr->seq) - cur->remote_start,
                           cur->remote_seq - cur->remote_start,
                           ntohl(tcphdr->ack_seq) - cur->local_start,
                           cur->local_seq - cur->local_start);
            }
        }

        else if (tcphdr->ack) {
            if (((uint32_t) ntohl(tcphdr->seq) + 1) == cur->remote_seq) {
                // TODO respond to keep alive?
                ng_log(ANDROID_LOG_DEBUG, "Keep alive");
                cur->time = time(NULL);
            } else if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                       ntohl(tcphdr->seq) == cur->remote_seq) {
                cur->time = time(NULL);

                if (cur->state == TCP_SYN_RECV) {
                    // TODO process data?
                    cur->state = TCP_ESTABLISHED;
                }
                else if (cur->state == TCP_ESTABLISHED) {
                    ng_log(ANDROID_LOG_DEBUG, "New ack data %u", datalen);
                    if (datalen) {
                        ng_log(ANDROID_LOG_DEBUG, "send socket data %u",
                               datalen);
                        // TODO non blocking
                        if (send(cur->socket, buffer + dataoff, datalen, 0) < 0) {
                            ng_log(ANDROID_LOG_ERROR, "send error %d: %s",
                                   errno, strerror(errno));
                            // Remote will retry
                        } else {
                            if (writeTCP(cur, NULL, 0, datalen, 0, 0, 0, args->tun) < 0) // ACK
                                ng_log(ANDROID_LOG_ERROR,
                                       "write data error %d: %s",
                                       errno, strerror((errno)));
                            else
                                cur->remote_seq += datalen; // received from tun
                        }
                    }
                }
                else if (cur->state == TCP_LAST_ACK) {
                    // socket has been shutdown already
                    cur->state = TCP_TIME_WAIT; // Will close socket
                }
                else if (cur->state == TCP_FIN_WAIT1)
                    cur->state = TCP_FIN_WAIT2;
                else if (cur->state == TCP_CLOSING)
                    cur->state = TCP_TIME_WAIT;
                else
                    ng_log(ANDROID_LOG_ERROR, "Invalid ACK state %s", strstate(cur->state));
            }
            else {
                // TODO proper wrap around
                if (ntohl(tcphdr->seq) == cur->remote_seq &&
                    ntohl(tcphdr->ack_seq) < cur->local_seq)
                    ng_log(ANDROID_LOG_INFO, "Previous ACK seq %u/%u ack %u/%u",
                           ntohl(tcphdr->seq) - cur->remote_start,
                           cur->remote_seq - cur->remote_start,
                           ntohl(tcphdr->ack_seq) - cur->local_start,
                           cur->local_seq - cur->local_start);
                else
                    ng_log(ANDROID_LOG_WARN, "Invalid ACK seq %u/%u ack %u/%u",
                           ntohl(tcphdr->seq) - cur->remote_start,
                           cur->remote_seq - cur->remote_start,
                           ntohl(tcphdr->ack_seq) - cur->local_start,
                           cur->local_seq - cur->local_start);
            }
        }

        else
            ng_log(ANDROID_LOG_ERROR, "Unknown packet");

        if (cur->state != oldstate || cur->local_seq != oldlocal || cur->remote_seq != oldremote)
            ng_log(ANDROID_LOG_DEBUG,
                   "Session lport %u new state %s local %u remote %u",
                   cur->lport, strstate(cur->state),
                   cur->local_seq - cur->local_start,
                   cur->remote_seq - cur->remote_start);
    }
}

int openSocket(JNIEnv *env, jobject instance, const struct sockaddr_in *daddr) {
    int sock = -1;

    // Get TCP socket
    // TODO socket options (SO_REUSEADDR, etc)
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        ng_log(ANDROID_LOG_ERROR, "socket error %d: %s",
               errno, strerror(errno));
        return -1;
    }

    // Protect
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
    if (mid == 0) {
        ng_log(ANDROID_LOG_ERROR, "protect not found");
        return -1;
    }
    else {
        jboolean isProtected = (*env)->CallBooleanMethod(env, instance, mid, sock);
        if (!isProtected)
            ng_log(ANDROID_LOG_ERROR, "protect failed");

        jthrowable ex = (*env)->ExceptionOccurred(env);
        if (ex) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, ex);
        }
    }

    // Set non blocking
    uint8_t flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        ng_log(ANDROID_LOG_ERROR, "fcntl O_NONBLOCK error %d: %s",
               errno, strerror(errno));
        return -1;
    }

    // Initiate connect
    int err = connect(sock, daddr, sizeof(struct sockaddr_in));
    if (err < 0 && errno != EINPROGRESS) {
        ng_log(ANDROID_LOG_ERROR, "connect error %d: %s",
               errno, strerror(errno));
        return -1;
    }

    // Set blocking
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        ng_log(ANDROID_LOG_ERROR, "fcntl error %d: %s",
               errno, strerror(errno));
        return -1;
    }

    return sock;
}

int getLocalPort(const int sock) {
    struct sockaddr_in sin;
    int len = sizeof(sin);
    if (getsockname(sock, &sin, &len) < 0) {
        ng_log(ANDROID_LOG_ERROR, "getsockname error %d: %s",
               errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

int writeTCP(const struct session *cur,
             uint8_t *data, uint16_t datalen, uint16_t confirm,
             int syn, int fin, int rst, int tun) {
    // Build packet
    uint16_t len = sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen;
    u_int8_t *buffer = calloc(len, 1);
    struct iphdr *ip = buffer;
    struct tcphdr *tcp = buffer + sizeof(struct iphdr);
    if (datalen)
        memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr), data, datalen);

    // Build IP header
    ip->version = 4;
    ip->ihl = sizeof(struct iphdr) >> 2;
    ip->tot_len = htons(len);
    ip->ttl = TCPTTL;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = cur->daddr;
    ip->daddr = cur->saddr;

    // Calculate IP checksum
    ip->check = checksum(ip, sizeof(struct iphdr));

    // Build TCP header
    tcp->source = cur->dest;
    tcp->dest = cur->source;
    tcp->seq = htonl(cur->local_seq);
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq + confirm));
    tcp->doff = sizeof(struct tcphdr) >> 2;
    tcp->syn = syn;
    tcp->ack = (datalen > 0 || confirm > 0 || syn);
    tcp->fin = fin;
    tcp->rst = rst;
    tcp->window = htons(TCPWINDOW);

    if (!tcp->ack)
        tcp->ack_seq = 0;

    // Calculate TCP checksum
    // TODO optimize memory usage
    uint16_t clen = sizeof(struct ippseudo) + sizeof(struct tcphdr) + datalen;
    uint8_t csum[clen];

    // Build pseudo header
    struct ippseudo *pseudo = csum;
    pseudo->ippseudo_src.s_addr = ip->saddr;
    pseudo->ippseudo_dst.s_addr = ip->daddr;
    pseudo->ippseudo_pad = 0;
    pseudo->ippseudo_p = ip->protocol;
    pseudo->ippseudo_len = htons(sizeof(struct tcphdr) + datalen);

    // Copy TCP header + data
    memcpy(csum + sizeof(struct ippseudo), tcp, sizeof(struct tcphdr));
    if (datalen)
        memcpy(csum + sizeof(struct ippseudo) + sizeof(struct tcphdr), data, datalen);

    tcp->check = checksum(csum, clen);

    char to[20];
    inet_ntop(AF_INET, &(ip->daddr), to, sizeof(to));

    // Send packet
    ng_log(ANDROID_LOG_DEBUG,
           "Sending%s%s%s%s to tun %s/%u seq %u ack %u data %u confirm %u",
           (tcp->syn ? " SYN" : ""),
           (tcp->ack ? " ACK" : ""),
           (tcp->fin ? " FIN" : ""),
           (tcp->rst ? " RST" : ""),
           to, ntohs(tcp->dest),
           ntohl(tcp->seq) - cur->local_start,
           ntohl(tcp->ack_seq) - cur->remote_start,
           datalen, confirm);
    int res = write(tun, buffer, len);

    if (pcap_fn != NULL) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts))
            ng_log(ANDROID_LOG_ERROR,
                   "clock_gettime error %d: %s",
                   errno, strerror(errno));

        int plen = (len < MAXPCAP ? len : MAXPCAP);
        struct pcaprec_hdr_s *pcap_rec = malloc(sizeof(struct pcaprec_hdr_s) + plen);

        pcap_rec->ts_sec = ts.tv_sec;
        pcap_rec->ts_usec = ts.tv_nsec / 1000;
        pcap_rec->incl_len = plen;
        pcap_rec->orig_len = len;
        memcpy(((uint8_t *) pcap_rec) + sizeof(struct pcaprec_hdr_s), buffer, plen);

        pcap_write(pcap_rec, sizeof(struct pcaprec_hdr_s) + plen);

        free(pcap_rec);
    }

    free(buffer);

    return res;
}

jint getUid(const int protocol, const int version, const void *saddr, const uint16_t sport) {
    char line[250];
    int fields;
    int32_t addr32;
    int8_t addr128[16];
    uint16_t port;
    jint uid = -1;

    // Get proc file name
    char *fn = NULL;
    if (protocol == IPPROTO_TCP)
        fn = (version == 4 ? "/proc/net/tcp" : "/proc/net/tcp6");
    else if (protocol == IPPROTO_UDP)
        fn = (version == 4 ? "/proc/net/udp" : "/proc/net/udp6");
    else
        return uid;

    // Open proc file
    FILE *fd = fopen(fn, "r");
    if (fd == NULL) {
        ng_log(ANDROID_LOG_ERROR, "fopen %s error %d: %s",
               fn, errno, strerror(errno));
        return uid;
    }

    // Scan proc file
    jint u;
    int i = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (i++) {
            if (version == 4)
                fields = sscanf(line,
                                "%*d: %X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                                &addr32, &port, &u);
            else
                fields = sscanf(line,
                                "%*d: %8X%8X%8X%8X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                                addr128, addr128 + 4, addr128 + 8, addr128 + 12, &port, &u);

            if (fields == (version == 4 ? 3 : 6)) {
                if (port == sport) {
                    if (version == 4) {
                        if (addr32 == *((int32_t *) saddr)) {
                            uid = u;
                            break;
                        }
                    }
                    else {
                        if (memcmp(addr128, saddr, (size_t) 16) == 0) {
                            uid = u;
                            break;
                        }
                    }
                }
            } else
                ng_log(ANDROID_LOG_ERROR, "Invalid field #%d: %s", fields, line);
        }
    }

    if (fclose(fd))
        ng_log(ANDROID_LOG_ERROR, "fclose %s error %d: %s",
               fn, errno, strerror(errno));

    return uid;
}

uint16_t checksum(uint8_t *buffer, uint16_t length) {
    register uint32_t sum = 0;
    register uint16_t *buf = buffer;
    register int len = length;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len > 0)
        sum += *((uint8_t *) buf);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) (~sum);
}

void ng_log(int prio, const char *fmt, ...) {
    if (prio >= loglevel) {
        char line[1024];
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        __android_log_print(prio, TAG, line);
        va_end(argptr);
    }
}

const char *strstate(const int state) {
    char buf[20];
    switch (state) {
        case TCP_ESTABLISHED:
            return "TCP_ESTABLISHED";
        case TCP_SYN_SENT:
            return "TCP_SYN_SENT";
        case TCP_SYN_RECV:
            return "TCP_SYN_RECV";
        case TCP_FIN_WAIT1:
            return "TCP_FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "TCP_FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TCP_TIME_WAIT";
        case TCP_CLOSE:
            return "TCP_CLOSE";
        case TCP_CLOSE_WAIT:
            return "TCP_CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "TCP_LAST_ACK";
        case TCP_LISTEN:
            return "TCP_LISTEN";
        case  TCP_CLOSING:
            return "TCP_CLOSING";
        default:
            sprintf(buf, "TCP_%d", state);
            return buf;

    }
}

char *hex(const u_int8_t *data, const u_int16_t len) {
    char hex_str[] = "0123456789ABCDEF";

    char *hexout;
    hexout = (char *) malloc(len * 3 + 1); // TODO free

    for (size_t i = 0; i < len; i++) {
        hexout[i * 3 + 0] = hex_str[(data[i] >> 4) & 0x0F];
        hexout[i * 3 + 1] = hex_str[(data[i]) & 0x0F];
        hexout[i * 3 + 2] = ' ';
    }
    return hexout;
}
