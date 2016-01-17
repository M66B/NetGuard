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
// TODO log allowed traffic
// TODO header file
// TODO debug switches
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

void *handle_events(void *);

void handle_ip(JNIEnv *, jobject, const struct arguments *, const uint8_t *, const uint16_t);

void handle_tcp(JNIEnv *, jobject, const struct arguments *args,
                const uint8_t *, const uint16_t, int uid);

int openSocket(JNIEnv *, jobject, const struct sockaddr_in *);

int getLocalPort(const int);

int canWrite(const int);

int writeTCP(const struct session *, uint8_t *, uint16_t, uint16_t, int, int, int, int);

jint getUid(const int, const int, const void *, const uint16_t);

uint16_t checksum(uint8_t *, uint16_t);

const char *strstate(const int state);

char *hex(const u_int8_t *, const u_int16_t);

// Global variables

static JavaVM *jvm;
pthread_t thread_id;
int signaled = 0;
struct session *session = NULL;

// JNI

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Init");
    session = NULL;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1start(JNIEnv *env, jobject instance,
                                                     jint tun) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Starting tun=%d", tun);

    if (pthread_kill(thread_id, 0) == 0)
        __android_log_print(ANDROID_LOG_WARN, TAG, "Already running thread %u", thread_id);
    else {
        jint rs = (*env)->GetJavaVM(env, &jvm);
        if (rs != JNI_OK)
            __android_log_print(ANDROID_LOG_ERROR, TAG, "GetJavaVM failed");

        struct arguments *args = malloc(sizeof(struct arguments));
        args->instance = (*env)->NewGlobalRef(env, instance);
        args->tun = tun;
        int err = pthread_create(&thread_id, NULL, handle_events, args);
        if (err != 0)
            __android_log_print(ANDROID_LOG_ERROR, TAG, "pthread_create error %d: %s",
                                err, strerror(err));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1stop(JNIEnv *env, jobject instance,
                                                    jint tun, jboolean clear) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Stop tun %d clear %d", tun, clear);
    if (pthread_kill(thread_id, 0) == 0) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Kill thread %u", thread_id);
        int err = pthread_kill(thread_id, SIGUSR1);
        if (err != 0)
            __android_log_print(ANDROID_LOG_WARN, TAG, "pthread_kill error %d: %s",
                                err, strerror(err));
        else {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Join thread %u", thread_id);
            pthread_join(thread_id, NULL);
            if (err != 0)
                __android_log_print(ANDROID_LOG_WARN, TAG, "pthread_join error %d: %s",
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
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Stopped");
    } else
        __android_log_print(ANDROID_LOG_WARN, TAG, "Not running");
}

// Private functions

void sig_handler(int sig, siginfo_t *info, void *context) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Signal %d", sig);
    signaled = 1;
}

void *handle_events(void *a) {
    struct arguments *args = (struct arguments *) a;
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Start events tun=%d thread %u", args->tun,
                        thread_id);

    JNIEnv *env;
    jint rs = (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    if (rs != JNI_OK)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "AttachCurrentThread failed");

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
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Loop thread %u", thread_id);

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
                __android_log_print(ANDROID_LOG_WARN, TAG, "Idle lport %u",
                                    cur->lport);
                if (cur->state == TCP_SYN_RECV ||
                    cur->state == TCP_ESTABLISHED ||
                    cur->state == TCP_CLOSE_WAIT) {
                    // TODO can write
                    if (writeTCP(cur, NULL, 0, 0, 0, 1, 0, args->tun) < 0) { // FIN
                        __android_log_print(ANDROID_LOG_ERROR, TAG,
                                            "write FIN lport %u error %d: %s",
                                            cur->lport, errno, strerror((errno)));
                        cur->state = TCP_TIME_WAIT; // Will close socket
                    }
                    else {
                        __android_log_print(ANDROID_LOG_DEBUG, TAG,
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
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "Close lport %u",
                                    cur->lport);

                // TODO keep for some time

                // TODO non blocking?
                if (close(cur->socket))
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "close error %d: %s",
                                        errno, strerror(errno));
                else
                    cur->state = TCP_CLOSE;

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
                    FD_SET(cur->socket, &wfds);
                    if (cur->socket > max)
                        max = cur->socket;
                }
                else if (cur->state == TCP_ESTABLISHED ||
                         cur->state == TCP_SYN_RECV ||
                         cur->state == TCP_CLOSE_WAIT) {
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
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "pselect signaled");
                    break;
                } else {
                    __android_log_print(ANDROID_LOG_WARN, TAG, "pselect interrupted");
                    continue;
                }
            } else {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "pselect error %d: %s",
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
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "pselect timeout sessions %d", sessions);
        else {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "pselect sessions %d ready %d",
                                sessions, ready);

            // Check tun exception
            if (FD_ISSET(args->tun, &efds)) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "tun exception");
                break;
            }

            // Check tun read
            if (FD_ISSET(args->tun, &rfds)) {
                uint8_t buffer[MAXPKT];
                ssize_t length = read(args->tun, buffer, MAXPKT);
                if (length < 0) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "tun read error %d: %s",
                                        errno, strerror(errno));
                    if (errno == EINTR)
                        continue;
                    else
                        break;
                }
                if (length > 0)
                    handle_ip(env, args->instance, args, buffer, length);
                else {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "tun empty read");
                    break;
                }
            }

            // Check sockets
            struct session *cur = session;
            while (cur != NULL) {
                // Check socket exception
                if (FD_ISSET(cur->socket, &efds)) {
                    int serr;
                    socklen_t optlen = sizeof(serr);
                    if (getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen) < 0) {
                        __android_log_print(ANDROID_LOG_ERROR, TAG,
                                            "getsockopt lport %u error %d: %s",
                                            cur->lport, errno, strerror(errno));
                        // TODO initiate finish
                        cur->state = TCP_TIME_WAIT; // will close socket
                        cur = cur->next;
                        continue;
                    }
                    if (serr) {
                        __android_log_print(ANDROID_LOG_ERROR, TAG, "lport %u SO_ERROR %d: %s",
                                            cur->lport, serr, strerror(serr));
                        // TODO initiate FIN
                        if (serr != EINTR)
                            cur->state = TCP_TIME_WAIT; // will close socket
                        cur = cur->next;
                        continue;
                    }
                }

                if (cur->state == TCP_LISTEN) {
                    // Check socket connect
                    if (FD_ISSET(cur->socket, &wfds) && canWrite(args->tun)) {
                        // Log
                        char dest[20];
                        inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
                        __android_log_print(ANDROID_LOG_DEBUG, TAG, "Connected lport %u %s/%u",
                                            cur->lport, dest, ntohs(cur->dest));

                        // TODO can write
                        if (writeTCP(cur, NULL, 0, 1, 1, 0, 0, args->tun) < 0) { // SYN+ACK
                            __android_log_print(ANDROID_LOG_ERROR, TAG,
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
                        if (bytes <= 0) {
                            // Socket remotely closed / error
                            if (bytes < 0) {
                                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                                    "recv lport %u error %d: %s",
                                                    cur->lport, errno, strerror(errno));
                                if (errno == EINTR) {
                                    cur = cur->next;
                                    continue;
                                }
                            }
                            else
                                __android_log_print(ANDROID_LOG_DEBUG, TAG, "recv lport %u empty",
                                                    cur->lport);

                            // TODO can write
                            if (writeTCP(cur, NULL, 0, 0, 0, 1, 0, args->tun) < 0) // FIN
                                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                                    "write FIN lport %u error %d: %s",
                                                    cur->lport, errno, strerror((errno)));
                            else {
                                __android_log_print(ANDROID_LOG_DEBUG, TAG,
                                                    "Half close initiated");
                                cur->local_seq++; // local FIN
                                if (cur->state == TCP_SYN_RECV || cur->state == TCP_ESTABLISHED)
                                    cur->state = TCP_FIN_WAIT1;
                                else // close wait
                                    cur->state = TCP_LAST_ACK;
                            }
                        } else {
                            __android_log_print(ANDROID_LOG_DEBUG, TAG,
                                                "recv lport %u bytes %d",
                                                cur->lport, bytes);
                            // TODO can write
                            if (writeTCP(cur, buffer, bytes, 0, 0, 0, 0, args->tun) < 0) // ACK
                                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                                    "write ACK lport %u error %d: %s",
                                                    cur->lport, errno, strerror((errno)));
                            else
                                cur->local_seq += bytes; // received from socket
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
        __android_log_print(ANDROID_LOG_ERROR, TAG, "DetachCurrentThread failed");
    free(args);

    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Stopped events tun=%d thread %u",
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
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid length %u header length %u",
                                length, ntohs(ip4hdr->tot_len));
            return;
        }

        uint16_t csum = checksum(ip4hdr, sizeof(struct iphdr));
        if (csum != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid IP checksum");
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
        __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown version %d", version);
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
        if (tcp->fin)
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

    __android_log_print(ANDROID_LOG_DEBUG, TAG,
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
            __android_log_print(ANDROID_LOG_ERROR, TAG, "logPacket not found");
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
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "optlen %d", optlen);

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
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Received %s/%u seq %u ack %u window %u data %d",
                        dest, ntohs(tcphdr->dest),
                        ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
                        ntohs(tcphdr->window), datalen);

    if (cur == NULL) {
        if (tcphdr->syn) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "New SYN");

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

                __android_log_print(ANDROID_LOG_DEBUG, TAG, "Connecting to %s/%u lport %u",
                                    dest, ntohs(tcphdr->dest), syn->lport);
                if (last == NULL)
                    session = syn;
                else
                    last->next = syn;
            }
        }
        else {
            __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown session");
            struct session *rst = malloc(sizeof(struct session));
            rst->time = time(NULL);
            rst->remote_seq = ntohl(tcphdr->seq);
            rst->local_seq = 0;
            rst->saddr = iphdr->saddr;
            rst->source = tcphdr->source;
            rst->daddr = iphdr->daddr;
            rst->dest = tcphdr->dest;
            rst->state = TCP_TIME_WAIT;
            rst->next = NULL;

            // TODO can write
            int confirm = (tcphdr->syn || tcphdr->fin ? 1 : 0) + datalen;
            if (writeTCP(rst, NULL, 0, confirm, 0, 0, 1, args->tun) < 0)
                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                    "write RST error %d: %s",
                                    errno, strerror((errno)));
            free(rst);
        }
    }
    else {
        int oldstate = cur->state;
        uint32_t oldlocal = cur->local_seq;
        uint32_t oldremote = cur->remote_seq;

        __android_log_print(ANDROID_LOG_DEBUG, TAG,
                            "Session lport %u state %s local %u remote %u",
                            cur->lport, strstate(cur->state),
                            cur->local_seq - cur->local_start,
                            cur->remote_seq - cur->remote_start);

        if (tcphdr->syn)
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Ignoring repeated SYN");

        else if (tcphdr->ack && !tcphdr->fin) {
            // TODO proper wrap around
            if (ntohl(tcphdr->seq) + 1 == cur->remote_seq) {
                // TODO respond to keep alive?
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "Keep alive");
                cur->time = time(NULL);
            } else if (ntohl(tcphdr->ack_seq) < cur->local_seq ||
                       ntohl(tcphdr->seq) < cur->remote_seq)
                __android_log_print(ANDROID_LOG_WARN, TAG, "Old ack");
            else if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                     ntohl(tcphdr->seq) == cur->remote_seq) {
                cur->time = time(NULL);

                if (cur->state == TCP_SYN_RECV) {
                    // TODO process data?
                    cur->state = TCP_ESTABLISHED;
                }
                else if (cur->state == TCP_ESTABLISHED) {
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "New ack data %u", datalen);
                    if (datalen) {
                        __android_log_print(ANDROID_LOG_DEBUG, TAG, "send socket data %u",
                                            datalen);
                        // TODO non blocking
                        if (send(cur->socket, buffer + dataoff, datalen, 0) < 0) {
                            __android_log_print(ANDROID_LOG_ERROR, TAG, "send error %d: %s",
                                                errno, strerror(errno));
                            // Remote will retry
                        } else {
                            // TODO can write
                            if (writeTCP(cur, NULL, 0, datalen, 0, 0, 0, args->tun) < 0) // ACK
                                __android_log_print(ANDROID_LOG_ERROR, TAG,
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
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid ACK");
            }
            else {
                // TODO check old seq/ack
                __android_log_print(ANDROID_LOG_WARN, TAG, "Invalid seq/ack");
            }
        }

        else if (tcphdr->fin /* ack */) {
            if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                ntohl(tcphdr->seq) == cur->remote_seq) {
                cur->time = time(NULL);

                if (shutdown(cur->socket, SHUT_RD)) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "shutdown error %d: %s",
                                        errno, strerror(errno));
                    // Remote will retry
                }
                else {
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Shutdown socket");

                    int ok = 1;
                    if (tcphdr->ack && datalen) {
                        __android_log_print(ANDROID_LOG_DEBUG, TAG, "send socket data %u",
                                            datalen);
                        // TODO non blocking
                        if (send(cur->socket, buffer + dataoff, datalen, 0) < 0) {
                            __android_log_print(ANDROID_LOG_ERROR, TAG, "send error %d: %s",
                                                errno, strerror(errno));
                            ok = 0;
                        }
                    }

                    if (ok) {
                        // TODO can write
                        if (writeTCP(cur, NULL, 0, 1 + datalen, 0, 0, 0, args->tun) < 0) // ACK
                            __android_log_print(ANDROID_LOG_ERROR, TAG,
                                                "write ACK error %d: %s",
                                                errno, strerror((errno)));
                        else {
                            cur->remote_seq += 1 + datalen; // FIN + received from tun
                            // TODO check ACK !TCP_FIN_WAIT1
                            if (cur->state == TCP_ESTABLISHED)
                                cur->state = TCP_CLOSE_WAIT;
                            else if (cur->state == TCP_FIN_WAIT1) {
                                if (tcphdr->ack)
                                    cur->state = TCP_TIME_WAIT;
                                else
                                    cur->state = TCP_CLOSING;
                            } else if (cur->state == TCP_FIN_WAIT2)
                                cur->state = TCP_TIME_WAIT;
                            else
                                __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid FIN");
                        }
                    }
                }
            }
            else {
                // TODO check old seq/ack
                __android_log_print(ANDROID_LOG_WARN, TAG, "Invalid seq/ack");
            }
        }

        else if (tcphdr->rst)
            cur->state = TCP_TIME_WAIT; // will close socket

        else
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Unknown packet");

        if (cur->state != oldstate || cur->local_seq != oldlocal || cur->remote_seq != oldremote)
            __android_log_print(ANDROID_LOG_DEBUG, TAG,
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
        __android_log_print(ANDROID_LOG_ERROR, TAG, "socket error %d: %s",
                            errno, strerror(errno));
        return -1;
    }

    // Protect
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
    if (mid == 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "protect not found");
        return -1;
    }
    else {
        jboolean isProtected = (*env)->CallBooleanMethod(env, instance, mid, sock);
        if (!isProtected)
            __android_log_print(ANDROID_LOG_ERROR, TAG, "protect failed");

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
        __android_log_print(ANDROID_LOG_ERROR, TAG, "fcntl O_NONBLOCK error %d: %s",
                            errno, strerror(errno));
        return -1;
    }

    // Initiate connect
    int err = connect(sock, daddr, sizeof(struct sockaddr_in));
    if (err < 0 && errno != EINPROGRESS) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "connect error %d: %s",
                            errno, strerror(errno));
        return -1;
    }

    // Set blocking
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "fcntl error %d: %s",
                            errno, strerror(errno));
        return -1;
    }

    return sock;
}

int getLocalPort(const int sock) {
    struct sockaddr_in sin;
    int len = sizeof(sin);
    if (getsockname(sock, &sin, &len) < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "getsockname error %d: %s",
                            errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

int canWrite(const int fd) {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    return (select(fd + 1, NULL, &wfds, NULL, &tv) > 0);
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
    tcp->ack_seq = htonl(cur->remote_seq + confirm); // TODO proper wrap around
    tcp->doff = sizeof(struct tcphdr) >> 2;
    tcp->syn = syn;
    // TODO why does a FIN need an ACK?
    tcp->ack = (datalen > 0 || confirm > 0 || syn || fin);
    tcp->fin = fin;
    tcp->rst = rst;
    tcp->window = htons(TCPWINDOW);

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
    __android_log_print(ANDROID_LOG_DEBUG, TAG,
                        "Sending%s%s%s%s to tun %s/%u seq %u ack %u data %u confirm %u",
                        (tcp->syn ? " SYN" : ""),
                        (tcp->ack ? " ACK" : ""),
                        (tcp->fin ? " FIN" : ""),
                        (tcp->rst ? " RST" : ""),
                        to, ntohs(tcp->dest),
                        ntohl(tcp->seq) - cur->local_start,
                        ntohl(tcp->ack_seq) - cur->remote_start,
                        datalen, confirm);
    //if (tcp->fin || tcp->rst) {
    //    char *h = hex(buffer, len);
    //    __android_log_print(ANDROID_LOG_DEBUG, TAG, "%s", h);
    //    free(h);
    //}
    int res = write(tun, buffer, len);

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
        __android_log_print(ANDROID_LOG_ERROR, TAG, "fopen %s error %d: %s",
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
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid field #%d: %s", fields, line);
        }
    }

    if (fclose(fd))
        __android_log_print(ANDROID_LOG_ERROR, TAG, "fclose %s error %d: %s",
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

