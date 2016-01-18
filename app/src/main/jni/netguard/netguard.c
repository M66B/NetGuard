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

#include "netguard.h"

#define PROFILE 1

// TODO TCP fragmentation
// TODO TCP push
// TODO TCPv6
// TODO UDPv4
// TODO UDPv6
// TODO DHCP
// TODO log allowed traffic
// TODO fix warnings
// TODO non blocking send/write, handle EAGAIN/EWOULDBLOCK

// Window size < 2^31: x <= y: (uint32_t)(y-x) < 0x80000000
// It is assumed that no packets will get lost and that packets arrive in order

// Global variables

static JavaVM *jvm;
pthread_t thread_id;
int signaled = 0;
struct session *session = NULL;
char *pcap_fn = NULL;
int loglevel = ANDROID_LOG_WARN;
int native = 0;

// JNI

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env) {
    session = NULL;
    pcap_fn = NULL;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1start(JNIEnv *env, jobject instance,
                                                     jint tun, jint loglevel_, jboolean native_) {
    loglevel = loglevel_;
    native = native_;

    log_android(ANDROID_LOG_INFO, "Starting tun=%d level %d native %d", tun, loglevel, native);

    // Set non blocking
    uint8_t flags = fcntl(tun, F_GETFL, 0);
    if (flags < 0 || fcntl(tun, F_SETFL, flags | O_NONBLOCK) < 0)
        log_android(ANDROID_LOG_ERROR, "fcntl tun O_NONBLOCK error %d: %s", errno, strerror(errno));

    if (pthread_kill(thread_id, 0) == 0)
        log_android(ANDROID_LOG_WARN, "Already running thread %lu", thread_id);
    else {
        jint rs = (*env)->GetJavaVM(env, &jvm);
        if (rs != JNI_OK)
            log_android(ANDROID_LOG_ERROR, "GetJavaVM failed");

        struct arguments *args = malloc(sizeof(struct arguments));
        args->instance = (*env)->NewGlobalRef(env, instance);
        args->tun = tun;
        int err = pthread_create(&thread_id, NULL, handle_events, args);
        if (err == 0)
            log_android(ANDROID_LOG_INFO, "Started thread %lu", thread_id);
        else
            log_android(ANDROID_LOG_ERROR, "pthread_create error %d: %s", err, strerror(err));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1stop(JNIEnv *env, jobject instance,
                                                    jint tun, jboolean clear) {
    log_android(ANDROID_LOG_INFO, "Stop tun %d clear %d", tun, (int) clear);
    if (pthread_kill(thread_id, 0) == 0) {
        log_android(ANDROID_LOG_DEBUG, "Kill thread %lu", thread_id);
        int err = pthread_kill(thread_id, SIGUSR1);
        if (err != 0)
            log_android(ANDROID_LOG_WARN, "pthread_kill error %d: %s", err, strerror(err));
        else {
            log_android(ANDROID_LOG_DEBUG, "Join thread %lu", thread_id);
            pthread_join(thread_id, NULL);
            if (err != 0)
                log_android(ANDROID_LOG_WARN, "pthread_join error %d: %s", err, strerror(err));
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
        log_android(ANDROID_LOG_INFO, "Stopped thread %lu", thread_id);
    } else
        log_android(ANDROID_LOG_WARN, "Not running");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1done(JNIEnv *env, jobject instance) {
    log_android(ANDROID_LOG_INFO, "Done");

    struct session *s = session;
    while (s != NULL) {
        struct session *p = s;
        s = s->next;
        free(p);
    }
    session = NULL;

    if (pcap_fn != NULL)
        free(pcap_fn);
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1pcap(JNIEnv *env, jclass type, jstring name_) {
    // TODO limit pcap file size
    // TODO keep pcap file open

    if (name_ == NULL) {
        pcap_fn = NULL;
        log_android(ANDROID_LOG_INFO, "PCAP disabled");
    }
    else {
        const char *name = (*env)->GetStringUTFChars(env, name_, 0);
        log_android(ANDROID_LOG_INFO, "PCAP file %s", name);

        const char *tmp = malloc(strlen(name) + 1);
        strcpy(tmp, name);
        pcap_fn = tmp;

        // Write pcap header
        session = NULL;
        struct pcap_hdr_s pcap_hdr;
        pcap_hdr.magic_number = 0xa1b2c3d4;
        pcap_hdr.version_major = 2;
        pcap_hdr.version_minor = 4;
        pcap_hdr.thiszone = 0;
        pcap_hdr.sigfigs = 0;
        pcap_hdr.snaplen = MAXPCAP;
        pcap_hdr.network = LINKTYPE_RAW;
        write_pcap(&pcap_hdr, sizeof(struct pcap_hdr_s));

        (*env)->ReleaseStringUTFChars(env, name_, name);
    }
}
// Private functions

void handle_signal(int sig, siginfo_t *info, void *context) {
    log_android(ANDROID_LOG_DEBUG, "Signal %d", sig);
    signaled = 1;
}

void handle_events(void *a) {
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    struct timespec ts;
    char dest[20];
    sigset_t blockset;
    sigset_t emptyset;
    struct sigaction sa;

    struct arguments *args = (struct arguments *) a;
    log_android(ANDROID_LOG_INFO, "Start events tun=%d thread %lu", args->tun, thread_id);

    // Attach to Java
    JNIEnv *env;
    jint rs = (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    if (rs != JNI_OK) {
        log_android(ANDROID_LOG_ERROR, "AttachCurrentThread failed");
        return;
    }
    args->env = env;

    // Block SIGUSR1
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blockset, NULL);

    /// Handle SIGUSR1
    sa.sa_sigaction = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    signaled = 0;

    // Loop
    while (1) {
        log_android(ANDROID_LOG_DEBUG, "Loop thread %lu", thread_id);

        // Select
        ts.tv_sec = SELECTWAIT;
        ts.tv_nsec = 0;
        // TODO let timeout depend on session timeouts
        sigemptyset(&emptyset);
        int max = get_selects(args, &rfds, &wfds, &efds);
        int ready = pselect(max + 1, &rfds, &wfds, &efds, session == NULL ? NULL : &ts, &emptyset);
        if (ready < 0) {
            if (errno == EINTR) {
                if (signaled) { ;
                    log_android(ANDROID_LOG_DEBUG, "pselect signaled");
                    break;
                } else {
                    log_android(ANDROID_LOG_WARN, "pselect interrupted");
                    continue;
                }
            } else {
                log_android(ANDROID_LOG_ERROR, "pselect error %d: %s",
                            errno, strerror(errno));
                break;
            }
        }

        // Count sessions
        int sessions = 0;
        struct session *s = session;
        while (s != NULL) {
            sessions++;
            s = s->next;
        }

        if (ready == 0)
            log_android(ANDROID_LOG_DEBUG, "pselect timeout sessions %d", sessions);
        else {
            log_android(ANDROID_LOG_DEBUG, "pselect sessions %d ready %d", sessions, ready);

#ifdef PROFILE
            struct timeval start, end;
            float mselapsed;
            gettimeofday(&start, NULL);
#endif

            // Check upstream
            check_tun(args, &rfds, &wfds, &efds);

#ifdef PROFILE
            gettimeofday(&end, NULL);
            mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;
            if (mselapsed > 1)
                log_android(ANDROID_LOG_INFO, "tun %f", mselapsed);

            gettimeofday(&start, NULL);
#endif

            // Check downstream
            check_sockets(args, &rfds, &wfds, &efds);

#ifdef PROFILE
            gettimeofday(&end, NULL);
            mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;
            if (mselapsed > 1)
                log_android(ANDROID_LOG_INFO, "sockets %f", mselapsed);
        }
#endif
    }

    (*env)->DeleteGlobalRef(env, args->instance);
    rs = (*jvm)->DetachCurrentThread(jvm);
    if (rs != JNI_OK)
        log_android(ANDROID_LOG_ERROR, "DetachCurrentThread failed");
    free(args);

    log_android(ANDROID_LOG_INFO, "Stopped events tun=%d thread %lu", args->tun, thread_id);
    // TODO conditionally report to Java
}

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    time_t now = time(NULL);

    // Select
    FD_ZERO(rfds);
    FD_ZERO(wfds);
    FD_ZERO(efds);

    // Always read tun
    FD_SET(args->tun, rfds);
    FD_SET(args->tun, efds);

    int max = args->tun;

    struct session *last = NULL;
    struct session *cur = session;
    while (cur != NULL) {
        // TODO differentiate timeouts
        if (cur->state != TCP_TIME_WAIT && cur->time + TCPTIMEOUT < now) {
            // TODO send keep alives?
            char dest[20];
            inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));

            log_android(ANDROID_LOG_WARN, "Idle %s/%u lport %u",
                        dest, ntohs(cur->dest), cur->lport);

            write_rst(cur, args->tun);
        }

        if (cur->state == TCP_TIME_WAIT) {
            // Log
            char dest[20];
            inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
            log_android(ANDROID_LOG_INFO, "Close %s/%u lport %u",
                        dest, ntohs(cur->dest), cur->lport);

            // TODO keep for some time

            // TODO non blocking?
            if (close(cur->socket))
                log_android(ANDROID_LOG_ERROR, "close error %d: %s", errno, strerror(errno));

            if (last == NULL)
                session = cur->next;
            else
                last->next = cur->next;

            struct session *c = cur;
            cur = cur->next;
            free(c);
            continue;

        } else if (cur->state == TCP_LISTEN) {
            // Check for connected / errors
            FD_SET(cur->socket, efds);
            FD_SET(cur->socket, wfds);
            if (cur->socket > max)
                max = cur->socket;
        }
        else if (cur->state == TCP_ESTABLISHED ||
                 cur->state == TCP_SYN_RECV ||
                 cur->state == TCP_CLOSE_WAIT) {
            // Check for data / errors
            FD_SET(cur->socket, efds);
            FD_SET(cur->socket, rfds);
            if (cur->socket > max)
                max = cur->socket;
        }

        last = cur;
        cur = cur->next;
    }

    return max;
}

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    // Check tun error
    if (FD_ISSET(args->tun, efds)) {
        log_android(ANDROID_LOG_ERROR, "tun exception");
        return -1; // over and out
    }

    // Check tun read
    if (FD_ISSET(args->tun, rfds)) {
        uint8_t buffer[MAXPKT];
        ssize_t length = read(args->tun, buffer, MAXPKT);
        if (length < 0) {
            log_android(ANDROID_LOG_ERROR, "tun read error %d: %s", errno, strerror(errno));
            return (errno == EINTR ? 0 : -1);
        }
        else if (length > 0) {
            // Write pcap record
            if (native && pcap_fn != NULL) {
                struct timespec ts;
                if (clock_gettime(CLOCK_REALTIME, &ts))
                    log_android(ANDROID_LOG_ERROR, "clock_gettime error %d: %s",
                                errno, strerror(errno));

                // TODO use stack
                int plen = (length < MAXPCAP ? length : MAXPCAP);
                struct pcaprec_hdr_s *pcap_rec =
                        malloc(sizeof(struct pcaprec_hdr_s) + plen);

                pcap_rec->ts_sec = ts.tv_sec;
                pcap_rec->ts_usec = ts.tv_nsec / 1000;
                pcap_rec->incl_len = plen;
                pcap_rec->orig_len = length;
                memcpy(((uint8_t *) pcap_rec) + sizeof(struct pcaprec_hdr_s), buffer, plen);

                write_pcap(pcap_rec, sizeof(struct pcaprec_hdr_s) + plen);

                free(pcap_rec);
            }

            // Handle IP from tun
            handle_ip(args, buffer, length);
        }
        else {
            // tun eof
            log_android(ANDROID_LOG_ERROR, "tun empty read");
            return -1;
        }
    }

    return 0;
}

void check_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct session *cur = session;
    while (cur != NULL) {
        int oldstate = cur->state;
        uint32_t oldlocal = cur->local_seq;
        uint32_t oldremote = cur->remote_seq;

        if (FD_ISSET(cur->socket, efds)) {
            // Socket error
            int serr = 0;
            socklen_t optlen = sizeof(int);
            int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
            if (err < 0)
                log_android(ANDROID_LOG_ERROR, "getsockopt lport %u error %d: %s",
                            cur->lport, errno, strerror(errno));
            else if (serr)
                log_android(ANDROID_LOG_ERROR, "lport %u SO_ERROR %d: %s",
                            cur->lport, serr, strerror(serr));

            write_rst(cur, args->tun);
        }
        else {
            // Assume socket okay
            if (cur->state == TCP_LISTEN) {
                // Check socket connect
                if (FD_ISSET(cur->socket, wfds)) {
                    // Log
                    char dest[20];
                    inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
                    log_android(ANDROID_LOG_INFO, "Connected %s/%u lport %u",
                                dest, ntohs(cur->dest), cur->lport);

                    if (write_syn_ack(cur, args->tun) >= 0) {
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
                if (FD_ISSET(cur->socket, rfds)) {
                    // TODO window size
                    uint8_t buffer[MAXPKT];
                    ssize_t bytes = recv(cur->socket, buffer, MAXPKT, 0);
                    if (bytes < 0) {
                        // Socket error
                        log_android(ANDROID_LOG_ERROR, "recv lport %u error %d: %s",
                                    cur->lport, errno, strerror(errno));

                        if (errno != EINTR)
                            write_rst(cur, args->tun);
                    }
                    else if (bytes == 0) {
                        // Socket eof
                        // TCP: application close
                        log_android(ANDROID_LOG_DEBUG, "recv empty lport %u state %s",
                                    cur->lport, strstate(cur->state));

                        if (write_fin(cur, args->tun) >= 0) {
                            // Shutdown socket for reading
                            if (shutdown(cur->socket, SHUT_RD))
                                log_android(ANDROID_LOG_WARN, "shutdown RD error %d: %s",
                                            errno, strerror(errno));

                            cur->local_seq++; // local FIN

                            if (cur->state == TCP_SYN_RECV || cur->state == TCP_ESTABLISHED)
                                cur->state = TCP_FIN_WAIT1;
                            else if (cur->state == TCP_CLOSE_WAIT)
                                cur->state = TCP_LAST_ACK;
                            else
                                log_android(ANDROID_LOG_ERROR, "Unknown state %s",
                                            strstate(cur->state));

                            log_android(ANDROID_LOG_DEBUG, "Half close state %s",
                                        strstate(cur->state));
                        }
                    } else {
                        // Socket read data
                        log_android(ANDROID_LOG_DEBUG,
                                    "recv lport %u bytes %d state %s",
                                    cur->lport, bytes, strstate(cur->state));

                        // Forward to tun
                        if (write_data(cur, buffer, bytes, args->tun) >= 0)
                            cur->local_seq += bytes;
                    }
                }
            }
        }

        if (cur->state != oldstate || cur->local_seq != oldlocal || cur->remote_seq != oldremote) {
            char dest[20];
            inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
            log_android(ANDROID_LOG_INFO,
                        "Session %s/%u lport %u new state %s local %u remote %u",
                        dest, ntohs(cur->dest), cur->lport, strstate(cur->state),
                        cur->local_seq - cur->local_start,
                        cur->remote_seq - cur->remote_start);
        }

        cur = cur->next;
    }
}

void handle_ip(const struct arguments *args, const uint8_t *buffer, const uint16_t length) {
    uint8_t protocol;
    void *saddr;
    void *daddr;
    char source[40];
    char dest[40];
    char flags[10];
    int flen = 0;
    uint8_t *payload;

#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

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
            log_android(ANDROID_LOG_ERROR, "Invalid length %u header length %u",
                        length, ntohs(ip4hdr->tot_len));
            return;
        }

        uint16_t csum = calc_checksum(ip4hdr, sizeof(struct iphdr));
        if (csum != 0) {
            log_android(ANDROID_LOG_ERROR, "Invalid IP checksum");
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
        log_android(ANDROID_LOG_WARN, "Unknown version %d", version);
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
    if ((protocol == IPPROTO_TCP && (syn || !native)) || protocol == IPPROTO_UDP) {
        int tries = 0;
        while (uid < 0 && tries++ < UIDTRIES) {
            // Most likely in IPv6 table
            int8_t saddr128[16];
            memset(saddr128, 0, 10);
            saddr128[10] = 0xFF;
            saddr128[11] = 0xFF;
            memcpy(saddr128 + 12, saddr, 4);
            uid = get_uid(protocol, 6, saddr128, sport);

            // Fallback to IPv4 table
            if (uid < 0 && version == 4)
                uid = get_uid(protocol, version, saddr, sport);

            // Retry delay
            if (uid < 0 && tries < UIDTRIES) {
                log_android(ANDROID_LOG_WARN, "get uid try %d", tries);
                usleep(1000 * UIDDELAY);
            }
        }

        if (uid < 0)
            log_android(ANDROID_LOG_WARN, "uid not found");
    }

    log_android(ANDROID_LOG_DEBUG,
                "Packet v%d %s/%u -> %s/%u proto %d flags %s uid %d",
                version, source, sport, dest, dport, protocol, flags, uid);

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "handle ip %f", mselapsed);
#endif

    if (protocol == IPPROTO_TCP && native)
        handle_tcp(args, buffer, length, uid);

    if ((protocol == IPPROTO_TCP && (syn || !native)) || protocol == IPPROTO_UDP)
        log_java(args, version, source, sport, dest, dport, protocol, flags, uid, 0);

}

void handle_tcp(const struct arguments *args, const uint8_t *buffer, uint16_t length, int uid) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Check version
    uint8_t version = (*buffer) >> 4;
    if (version != 4)
        return;

    // Get headers
    struct iphdr *iphdr = buffer;
    uint8_t optlen = (iphdr->ihl - 5) * 4;
    struct tcphdr *tcphdr = buffer + sizeof(struct iphdr) + optlen;
    if (optlen)
        log_android(ANDROID_LOG_INFO, "optlen %d", optlen);

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
    log_android(ANDROID_LOG_DEBUG, "Received %s/%u seq %u ack %u window %u data %d",
                dest, ntohs(tcphdr->dest),
                ntohl(tcphdr->seq) - (cur == NULL ? 0 : cur->remote_start),
                ntohl(tcphdr->ack_seq) - (cur == NULL ? 0 : cur->local_start),
                ntohs(tcphdr->window), datalen);

    if (cur == NULL) {
        if (tcphdr->syn) {
            log_android(ANDROID_LOG_INFO, "New session %s/%u uid %d",
                        dest, ntohs(tcphdr->dest), uid);

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
            if (datalen)
                log_android(ANDROID_LOG_WARN, "SYN session %s/%u data %u",
                            dest, ntohs(tcphdr->dest), datalen);

            // Open socket
            syn->socket = open_socket(syn, args);
            if (syn->socket < 0) {
                syn->state = TCP_TIME_WAIT;
                // Remote might retry
                free(syn);
            }
            else {
                syn->lport = get_local_port(syn->socket);

                if (last == NULL)
                    session = syn;
                else
                    last->next = syn;
            }
        }
        else {
            log_android(ANDROID_LOG_WARN, "Unknown session %s/%u uid %d",
                        dest, ntohs(tcphdr->dest), uid);

            struct session rst;
            memset(&rst, 0, sizeof(struct session));
            rst.remote_seq = ntohl(tcphdr->seq);
            rst.saddr = iphdr->saddr;
            rst.source = tcphdr->source;
            rst.daddr = iphdr->daddr;
            rst.dest = tcphdr->dest;
            write_rst(&rst, args->tun);
        }

#ifdef PROFILE
        gettimeofday(&end, NULL);
        mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                    (end.tv_usec - start.tv_usec) / 1000.0;
        if (mselapsed > 1)
            log_android(ANDROID_LOG_INFO, "new session %f", mselapsed);
#endif
    }
    else {
        // Session found
        int oldstate = cur->state;
        uint32_t oldlocal = cur->local_seq;
        uint32_t oldremote = cur->remote_seq;

        log_android(ANDROID_LOG_DEBUG,
                    "Session %s/%u lport %u state %s local %u remote %u",
                    dest, ntohs(cur->dest), cur->lport, strstate(cur->state),
                    cur->local_seq - cur->local_start,
                    cur->remote_seq - cur->remote_start);

        cur->time = time(NULL);

        // Do not change order of conditions

        if (tcphdr->rst) {
            log_android(ANDROID_LOG_INFO, "RST session %s/%u lport %u received",
                        dest, ntohs(cur->dest), cur->lport);
            cur->state = TCP_TIME_WAIT;
        }

        else if (tcphdr->syn) {
            log_android(ANDROID_LOG_WARN, "Repeated SYN session %s/%u lport %u",
                        dest, ntohs(cur->dest), cur->lport);
            // Note: perfect, ordered packet receive assumed

        } else if (tcphdr->fin /* ACK */) {
            if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                ntohl(tcphdr->seq) == cur->remote_seq) {

                if (datalen)
                    log_android(ANDROID_LOG_WARN, "FIN session %s/%u lport %u data %u",
                                dest, ntohs(cur->dest), cur->lport, datalen);

                // Forward last data to socket
                int ok = 1;
                if (tcphdr->ack && datalen) {
                    log_android(ANDROID_LOG_DEBUG, "send socket data %u", datalen);

                    if (send_socket(cur->socket, buffer + dataoff, datalen) < 0)
                        ok = 0;
                }

                // Shutdown socket for writing
                if (shutdown(cur->socket, SHUT_WR)) {
                    log_android(ANDROID_LOG_ERROR, "shutdown WR error %d: %s",
                                errno, strerror(errno));
                    ok = 0;
                    // Data might be lost
                }

                if (ok) {
                    if (write_ack(cur, 1 + datalen, args->tun) >= 0) {
                        cur->remote_seq += (1 + datalen); // FIN + data from tun
                        if (cur->state == TCP_ESTABLISHED /* && !tcphdr->ack */)
                            cur->state = TCP_CLOSE_WAIT;
                        else if (cur->state == TCP_FIN_WAIT1 && tcphdr->ack)
                            cur->state = TCP_TIME_WAIT;
                        else if (cur->state == TCP_FIN_WAIT1 && !tcphdr->ack)
                            cur->state = TCP_CLOSING;
                        else if (cur->state == TCP_FIN_WAIT2 /* && !tcphdr->ack */)
                            cur->state = TCP_TIME_WAIT;
                        else
                            log_android(ANDROID_LOG_ERROR,
                                        "Invalid FIN session %s/%u lport %u state %s ACK %d",
                                        dest, ntohs(cur->dest), cur->lport,
                                        strstate(cur->state), tcphdr->ack);
                    }
                } else
                    write_rst(cur, args->tun);
            }
            else {
                // Special case or hack if you like

                // TODO proper wrap around
                if (cur->state == TCP_FIN_WAIT1 &&
                    ntohl(tcphdr->seq) == cur->remote_seq &&
                    ntohl(tcphdr->ack_seq) < cur->local_seq) {
                    int confirm = cur->local_seq - ntohl(tcphdr->ack_seq);
                    log_android(ANDROID_LOG_INFO, "Simultaneous close %s/%u lport %u confirm %d",
                                dest, ntohs(cur->dest), cur->lport, confirm);
                    write_ack(cur, confirm, args->tun);
                }
                else
                    log_android(ANDROID_LOG_WARN,
                                "Invalid FIN session %s/%u lport %u state %s seq %u/%u ack %u/%u",
                                dest, ntohs(cur->dest), cur->lport, strstate(cur->state),
                                ntohl(tcphdr->seq) - cur->remote_start,
                                cur->remote_seq - cur->remote_start,
                                ntohl(tcphdr->ack_seq) - cur->local_start,
                                cur->local_seq - cur->local_start);
            }
        }

        else if (tcphdr->ack) {
            if (((uint32_t) ntohl(tcphdr->seq) + 1) == cur->remote_seq) {
                log_android(ANDROID_LOG_INFO, "Keep alive session %s/%u lport %u",
                            dest, ntohs(cur->dest), cur->lport);

            } else if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                       ntohl(tcphdr->seq) == cur->remote_seq) {

                if (cur->state == TCP_SYN_RECV) {
                    // TODO process data?
                    // Remote will retry
                    cur->state = TCP_ESTABLISHED;
                }
                else if (cur->state == TCP_ESTABLISHED) {
                    log_android(ANDROID_LOG_DEBUG, "New ACK session %s/%u lport %u data %u",
                                dest, ntohs(cur->dest), cur->lport, datalen);

                    // Forward data to socket
                    if (datalen) {
                        log_android(ANDROID_LOG_DEBUG, "send socket data %u", datalen);
                        if (send_socket(cur->socket, buffer + dataoff, datalen) < 0)
                            write_rst(cur, args->tun);
                        else {
                            if (write_ack(cur, datalen, args->tun) >= 0)
                                cur->remote_seq += datalen;
                        }
                    }
                }
                else if (cur->state == TCP_LAST_ACK) {
                    // socket has been shutdown already
                    cur->state = TCP_TIME_WAIT;
                }
                else if (cur->state == TCP_FIN_WAIT1)
                    cur->state = TCP_FIN_WAIT2;
                else if (cur->state == TCP_CLOSING)
                    cur->state = TCP_TIME_WAIT;
                else
                    log_android(ANDROID_LOG_ERROR, "Invalid ACK session %s/%u lport %u state %s",
                                dest, ntohs(cur->dest), cur->lport, strstate(cur->state));
            }
            else {
                // TODO proper wrap around
                if (ntohl(tcphdr->seq) == cur->remote_seq &&
                    ntohl(tcphdr->ack_seq) < cur->local_seq)
                    log_android(ANDROID_LOG_INFO,
                                "Previous ACK session %s/%u lport %u seq %u/%u ack %u/%u",
                                dest, ntohs(cur->dest), cur->lport,
                                ntohl(tcphdr->seq) - cur->remote_start,
                                cur->remote_seq - cur->remote_start,
                                ntohl(tcphdr->ack_seq) - cur->local_start,
                                cur->local_seq - cur->local_start);
                else
                    log_android(ANDROID_LOG_WARN,
                                "Invalid ACK session %s/%u lport %u state %s seq %u/%u ack %u/%u",
                                dest, ntohs(cur->dest), cur->lport, strstate(cur->state),
                                ntohl(tcphdr->seq) - cur->remote_start,
                                cur->remote_seq - cur->remote_start,
                                ntohl(tcphdr->ack_seq) - cur->local_start,
                                cur->local_seq - cur->local_start);
            }
        }

        else
            log_android(ANDROID_LOG_ERROR, "Unknown packet session %s/%u lport %u",
                        dest, ntohs(cur->dest), cur->lport);

        if (cur->state != oldstate || cur->local_seq != oldlocal || cur->remote_seq != oldremote)
            log_android(ANDROID_LOG_INFO,
                        "Session %s/%u lport %u new state %s local %u remote %u",
                        dest, ntohs(cur->dest), cur->lport, strstate(cur->state),
                        cur->local_seq - cur->local_start,
                        cur->remote_seq - cur->remote_start);

#ifdef PROFILE
        gettimeofday(&end, NULL);
        mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                    (end.tv_usec - start.tv_usec) / 1000.0;
        if (mselapsed > 1)
            log_android(ANDROID_LOG_INFO, "existing session %f", mselapsed);
#endif
    }
}

int open_socket(const struct session *cur, const struct arguments *args) {
    int sock = -1;

    // Build target address
    struct sockaddr_in daddr;
    memset(&daddr, 0, sizeof(struct sockaddr_in));
    daddr.sin_family = AF_INET;
    daddr.sin_port = cur->dest;
    daddr.sin_addr.s_addr = cur->daddr;

    // Get TCP socket
    // TODO socket options (SO_REUSEADDR, etc)
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_android(ANDROID_LOG_ERROR, "socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect
    JNIEnv *env = args->env;
    jobject instance = args->instance;
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
    if (mid == 0) {
        log_android(ANDROID_LOG_ERROR, "protect not found");
        return -1;
    }
    else {
        jboolean isProtected = (*env)->CallBooleanMethod(env, instance, mid, sock);
        if (!isProtected)
            log_android(ANDROID_LOG_ERROR, "protect failed");

        jthrowable ex = (*env)->ExceptionOccurred(env);
        if (ex) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, ex);
        }
    }

    // Set tun blocking
    uint8_t flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        log_android(ANDROID_LOG_ERROR, "fcntl socket O_NONBLOCK error %d: %s",
                    errno, strerror(errno));
        return -1;
    }

    // Initiate connect
    int err = connect(sock, &daddr, sizeof(struct sockaddr_in));
    if (err < 0 && errno != EINPROGRESS) {
        log_android(ANDROID_LOG_ERROR, "connect error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Set blocking
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        log_android(ANDROID_LOG_ERROR, "fcntl socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    return sock;
}

int get_local_port(const int sock) {
    struct sockaddr_in sin;
    int len = sizeof(sin);
    if (getsockname(sock, &sin, &len) < 0) {
        log_android(ANDROID_LOG_ERROR, "getsockname error %d: %s", errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

ssize_t send_socket(int sock, uint8_t *buffer, uint16_t len) {
    // TODO non blocking
    ssize_t res = send(sock, buffer, len, 0);
    if (res < 0)
        log_android(ANDROID_LOG_ERROR, "send error %d: %s", errno, strerror(errno));
    return res;
}

int write_syn_ack(struct session *cur, int tun) {
    if (write_tcp(cur, NULL, 0, 1, 1, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write SYN+ACK error %d: %s",
                    errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

int write_ack(struct session *cur, int bytes, int tun) {
    if (write_tcp(cur, NULL, 0, bytes, 0, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write ACK error %d: %s",
                    errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

int write_data(struct session *cur, const uint8_t *buffer, uint16_t length, int tun) {
    if (write_tcp(cur, buffer, length, 0, 0, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write data ACK lport %u error %d: %s",
                    cur->lport, errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
    }

}

int write_fin(struct session *cur, int tun) {
    if (write_tcp(cur, NULL, 0, 0, 0, 1, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR,
                    "write FIN lport %u error %d: %s",
                    cur->lport, errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

void write_rst(struct session *cur, int tun) {
    log_android(ANDROID_LOG_WARN, "Sending RST");
    if (write_tcp(cur, NULL, 0, 0, 0, 0, 1, tun) < 0)
        log_android(ANDROID_LOG_ERROR, "write RST error %d: %s",
                    errno, strerror((errno)));
    cur->state = TCP_TIME_WAIT;
}

int write_tcp(const struct session *cur,
              uint8_t *data, uint16_t datalen, uint16_t confirm,
              int syn, int fin, int rst, int tun) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

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
    ip->check = calc_checksum(ip, sizeof(struct iphdr));

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

    tcp->check = calc_checksum(csum, clen);

    char to[20];
    inet_ntop(AF_INET, &(ip->daddr), to, sizeof(to));

    // Send packet
    log_android(ANDROID_LOG_DEBUG,
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

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "tun write %f", mselapsed);
#endif

    // Write pcap record
    if (native && pcap_fn != NULL) {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts))
            log_android(ANDROID_LOG_ERROR, "clock_gettime error %d: %s", errno, strerror(errno));

        // TODO use stack
        int plen = (len < MAXPCAP ? len : MAXPCAP);
        struct pcaprec_hdr_s *pcap_rec = malloc(sizeof(struct pcaprec_hdr_s) + plen);

        pcap_rec->ts_sec = ts.tv_sec;
        pcap_rec->ts_usec = ts.tv_nsec / 1000;
        pcap_rec->incl_len = plen;
        pcap_rec->orig_len = len;
        memcpy(((uint8_t *) pcap_rec) + sizeof(struct pcaprec_hdr_s), buffer, plen);

        write_pcap(pcap_rec, sizeof(struct pcaprec_hdr_s) + plen);

        free(pcap_rec);
    }

    free(buffer);

    return res;
}

jint get_uid(const int protocol, const int version, const void *saddr, const uint16_t sport) {
    char line[250];
    int fields;
    int32_t addr32;
    int8_t addr128[16];
    uint16_t port;
    jint uid = -1;

#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

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
        log_android(ANDROID_LOG_ERROR, "fopen %s error %d: %s", fn, errno, strerror(errno));
        return uid;
    }

    // Scan proc file
    jint u;
    int i = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (i++) {
            if (version == 4)
                fields = sscanf(
                        line,
                        "%*d: %X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                        &addr32, &port, &u);
            else
                fields = sscanf(
                        line,
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
                log_android(ANDROID_LOG_ERROR, "Invalid field #%d: %s", fields, line);
        }
    }

    if (fclose(fd))
        log_android(ANDROID_LOG_ERROR, "fclose %s error %d: %s", fn, errno, strerror(errno));

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "get uid ip %f", mselapsed);
#endif

    return uid;
}

uint16_t calc_checksum(uint8_t *buffer, uint16_t length) {
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

void log_android(int prio, const char *fmt, ...) {
    if (prio >= loglevel) {
        char line[1024];
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        __android_log_print(prio, TAG, line);
        va_end(argptr);
    }
}

void log_java(
        const struct arguments *args, uint8_t version,
        const char *source, uint16_t sport,
        const char *dest, uint16_t dport,
        uint8_t protocol, const char *flags,
        jint uid, jboolean allowed) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    JNIEnv *env = args->env;
    jobject instance = args->instance;
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(
            env, cls, "logPacket",
            "(ILjava/lang/String;ILjava/lang/String;IILjava/lang/String;IZ)V");
    if (mid == 0)
        log_android(ANDROID_LOG_ERROR, "logPacket not found");
    else {
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

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "log java %f", mselapsed);
#endif
}

void write_pcap(const void *ptr, size_t len) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    FILE *fd = fopen(pcap_fn, "ab");
    if (fd == NULL)
        log_android(ANDROID_LOG_ERROR, "fopen %s error %d: %s",
                    pcap_fn, errno, strerror(errno));
    else {
        if (fwrite(ptr, len, 1, fd) < 1)
            log_android(ANDROID_LOG_ERROR, "fwrite %s error %d: %s",
                        pcap_fn, errno, strerror(errno));
        else
            log_android(ANDROID_LOG_DEBUG, "PCAP write %d", len);

        if (fclose(fd))
            log_android(ANDROID_LOG_ERROR, "fclose %s error %d: %s",
                        pcap_fn, errno, strerror(errno));
    }

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "pcap write %f", mselapsed);
#endif
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
