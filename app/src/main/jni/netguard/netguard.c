/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2016 by Marcel Bokhorst (M66B)
*/

#include <jni.h>
#include <android/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "netguard.h"

// #define PROFILE 1

// TODO TCP options
// TODO TCP fragmentation
// TODO TCPv6
// TODO UDPv6
// TODO fix warnings
// TODO non blocking send/write/close, handle EAGAIN/EWOULDBLOCK

// It is assumed that no packets will get lost and that packets arrive in order

// Global variables

static JavaVM *jvm;
pthread_t thread_id;
jboolean stopping = 0;
jboolean signaled = 0;

struct udp_session *udp_session = NULL;
struct tcp_session *tcp_session = NULL;

int loglevel = 0;
FILE *pcap_file = NULL;

// JNI

jclass clsPacket;

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI load");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
        return -1;
    }

    const char *packet = "eu/faircode/netguard/Packet";
    clsPacket = jniGlobalRef(env, jniFindClass(env, packet));

    return JNI_VERSION_1_6;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI unload");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK)
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
    else {
        (*env)->DeleteGlobalRef(env, clsPacket);
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env) {
    udp_session = NULL;
    tcp_session = NULL;
    loglevel = ANDROID_LOG_WARN;
    pcap_file = NULL;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1start(
        JNIEnv *env, jobject instance,
        jint tun, jintArray uids_,
        jstring hosts_,
        jboolean log, jboolean filter,
        jint loglevel_) {

    loglevel = loglevel_;
    log_android(ANDROID_LOG_WARN, "Starting tun=%d log %d filter %d level %d",
                tun, log, filter, loglevel_);

    // Set blocking
    int flags = fcntl(tun, F_GETFL, 0);
    if (flags < 0 || fcntl(tun, F_SETFL, flags & ~O_NONBLOCK) < 0)
        log_android(ANDROID_LOG_ERROR, "fcntl tun ~O_NONBLOCK error %d: %s",
                    errno, strerror(errno));

    if (pthread_kill(thread_id, 0) == 0)
        log_android(ANDROID_LOG_WARN, "Already running thread %lu", thread_id);
    else {
        jint rs = (*env)->GetJavaVM(env, &jvm);
        if (rs != JNI_OK)
            log_android(ANDROID_LOG_ERROR, "GetJavaVM failed");

        // Get arguments
        struct arguments *args = malloc(sizeof(struct arguments));
        args->instance = (*env)->NewGlobalRef(env, instance);
        args->tun = tun;

        args->ucount = (*env)->GetArrayLength(env, uids_);
        args->uids = malloc(args->ucount * sizeof(jint));
        jint *uids = (*env)->GetIntArrayElements(env, uids_, NULL);
        memcpy(args->uids, uids, args->ucount * sizeof(jint));
        (*env)->ReleaseIntArrayElements(env, uids_, uids, 0);

        args->log = log;
        args->filter = filter;

        if (hosts_ == NULL) {
            args->hcount = 0;
            args->hosts = NULL;
            log_android(ANDROID_LOG_WARN, "No hosts file");
        } else {
            const char *hosts = (*env)->GetStringUTFChars(env, hosts_, 0);
            log_android(ANDROID_LOG_WARN, "hosts file %s", hosts);
            read_hosts(hosts, args);
            (*env)->ReleaseStringUTFChars(env, hosts_, hosts);
        }

        for (int i = 0; i < args->ucount; i++)
            log_android(ANDROID_LOG_DEBUG, "Allowed uid %d", args->uids[i]);

        // Start native thread
        int err = pthread_create(&thread_id, NULL, handle_events, (void *) args);
        if (err == 0)
            log_android(ANDROID_LOG_INFO, "Started thread %lu", thread_id);
        else
            log_android(ANDROID_LOG_ERROR, "pthread_create error %d: %s", err, strerror(err));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1stop(JNIEnv *env, jobject instance,
                                                    jint tun, jboolean clear) {
    log_android(ANDROID_LOG_WARN, "Stop tun %d clear %d", tun, (int) clear);
    if (pthread_kill(thread_id, 0) == 0) {
        stopping = 1;
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
        if (clear)
            clear_sessions();

        log_android(ANDROID_LOG_INFO, "Stopped thread %lu", thread_id);
    } else
        log_android(ANDROID_LOG_WARN, "Not running");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1done(JNIEnv *env, jobject instance) {
    log_android(ANDROID_LOG_INFO, "Done");

    clear_sessions();
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1pcap(JNIEnv *env, jclass type, jstring name_) {
    if (name_ == NULL) {
        if (pcap_file != NULL) {
            if (fclose(pcap_file))
                log_android(ANDROID_LOG_ERROR, "PCAP fclose error %d: %s", errno,
                            strerror(errno));
        }
        pcap_file = NULL;
        log_android(ANDROID_LOG_INFO, "PCAP disabled");
    }
    else {
        const char *name = (*env)->GetStringUTFChars(env, name_, 0);
        log_android(ANDROID_LOG_INFO, "PCAP file %s", name);

        pcap_file = fopen(name, "ab+");
        if (pcap_file == NULL)
            log_android(ANDROID_LOG_ERROR, "PCAP fopen error %d: %s", errno, strerror(errno));
        else {
            int flags = fcntl(fileno(pcap_file), F_GETFL, 0);
            if (flags < 0 || fcntl(fileno(pcap_file), F_SETFL, flags | O_NONBLOCK) < 0)
                log_android(ANDROID_LOG_ERROR, "PCAP fcntl O_NONBLOCK error %d: %s",
                            errno, strerror(errno));
            write_pcap_hdr();
        }

        (*env)->ReleaseStringUTFChars(env, name_, name);
    }
}

// Private functions

void clear_sessions() {
    struct udp_session *u = udp_session;
    while (u != NULL) {
        close(u->socket);
        struct udp_session *p = u;
        u = u->next;
        free(p);
    }
    udp_session = NULL;

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        close(t->socket);
        struct tcp_session *p = t;
        t = t->next;
        free(p);
    }
    tcp_session = NULL;
}

void handle_signal(int sig, siginfo_t *info, void *context) {
    log_android(ANDROID_LOG_DEBUG, "Signal %d", sig);
    signaled = 1;
}

void *handle_events(void *a) {
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    struct timespec ts;
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
        return NULL;
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

    stopping = 0;
    signaled = 0;

    // Loop
    while (1) {
        log_android(ANDROID_LOG_DEBUG, "Loop thread %lu", thread_id);

        // Check sessions
        check_sessions(args);

        // Select
        ts.tv_sec = SELECT_TIMEOUT;
        ts.tv_nsec = 0;
        sigemptyset(&emptyset);
        int max = get_selects(args, &rfds, &wfds, &efds);
        int ready = pselect(max + 1, &rfds, &wfds, &efds,
                            udp_session == NULL && tcp_session == NULL ? NULL : &ts,
                            &emptyset);
        if (ready < 0) {
            if (errno == EINTR) {
                if (stopping && signaled) { ;
                    log_android(ANDROID_LOG_WARN, "pselect signaled");
                    break;
                } else {
                    log_android(ANDROID_LOG_DEBUG, "pselect interrupted");
                    continue;
                }
            } else {
                log_android(ANDROID_LOG_ERROR, "pselect error %d: %s", errno, strerror(errno));
                break;
            }
        }

        // Count sessions
        int udp = 0;
        struct udp_session *u = udp_session;
        while (u != NULL) {
            udp++;
            u = u->next;
        }

        int tcp = 0;
        struct tcp_session *t = tcp_session;
        while (t != NULL) {
            tcp++;
            t = t->next;
        }

        if (ready == 0)
            log_android(ANDROID_LOG_DEBUG, "pselect timeout udp %d tcp %d", udp, tcp);
        else {
            log_android(ANDROID_LOG_DEBUG, "pselect udp %d tcp %d ready %d", udp, tcp, ready);

#ifdef PROFILE
            struct timeval start, end;
            float mselapsed;
            gettimeofday(&start, NULL);
#endif

            // Check upstream
            if (check_tun(args, &rfds, &wfds, &efds) < 0)
                break;

#ifdef PROFILE
            gettimeofday(&end, NULL);
            mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;
            if (mselapsed > 1)
                log_android(ANDROID_LOG_INFO, "tun %f", mselapsed);

            gettimeofday(&start, NULL);
#endif

            // Check UDP downstream
            check_udp_sockets(args, &rfds, &wfds, &efds);

            // Check TCP downstream
            check_tcp_sockets(args, &rfds, &wfds, &efds);

#ifdef PROFILE
            gettimeofday(&end, NULL);
            mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;
            if (mselapsed > 1)
                log_android(ANDROID_LOG_INFO, "sockets %f", mselapsed);
#endif
        }
    }

    // Report exit to Java
    report_exit(args);

    (*env)->DeleteGlobalRef(env, args->instance);

    // Detach from Java
    rs = (*jvm)->DetachCurrentThread(jvm);
    if (rs != JNI_OK)
        log_android(ANDROID_LOG_ERROR, "DetachCurrentThread failed");

    // Cleanup
    free(args->uids);
    for (int i = 0; i < args->hcount; i++)
        free(args->hosts[i]);
    free(args->hosts);
    free(args);

    log_android(ANDROID_LOG_WARN, "Stopped events tun=%d thread %lu", args->tun, thread_id);
    return NULL;
}

void report_exit(struct arguments *args) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    jmethodID mid = jniGetMethodID(args->env, cls, "selectExit", "(Z)V");

    jboolean planned = stopping;
    (*args->env)->CallVoidMethod(args->env, args->instance, mid, planned);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, cls);
}

void check_sessions(const struct arguments *args) {
    time_t now = time(NULL);

    // Check UDP sessions
    struct udp_session *ul = NULL;
    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->error || u->time + UDP_TIMEOUT < now) {
            log_android(ANDROID_LOG_WARN, "UDP timeout");

            if (close(u->socket))
                log_android(ANDROID_LOG_ERROR, "UDP close error %d: %s", errno, strerror(errno));

            if (ul == NULL)
                udp_session = u->next;
            else
                ul->next = u->next;

            struct udp_session *c = u;
            u = u->next;
            free(c);
        }
        else {
            ul = u;
            u = u->next;
        }
    }

    // Check TCP sessions
    struct tcp_session *tl = NULL;
    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        char source[20];
        char dest[20];
        inet_ntop(AF_INET, &(t->saddr), source, sizeof(source));
        inet_ntop(AF_INET, &(t->daddr), dest, sizeof(dest));

        // Check connection timeout
        int timeout = 0;
        if (t->state == TCP_LISTEN || t->state == TCP_SYN_RECV)
            timeout = TCP_INIT_TIMEOUT;
        else if (t->state == TCP_ESTABLISHED)
            timeout = TCP_IDLE_TIMEOUT;
        else
            timeout = TCP_CLOSE_TIMEOUT;
        if (t->state != TCP_TIME_WAIT && t->state != TCP_CLOSE && t->time + timeout < now) {
            // TODO send keep alives?
            log_android(ANDROID_LOG_WARN, "Idle from %s/%u to %s/%u state %s",
                        dest, ntohs(t->dest), source, ntohs(t->source), strstate(t->state));

            write_rst(args, t, args->tun);
        }

        // Check finished connection
        if (t->state == TCP_TIME_WAIT) {
            log_android(ANDROID_LOG_INFO, "Close from %s/%u to %s/%u socket %d",
                        source, ntohs(t->source), dest, ntohs(t->dest), t->socket);

            if (close(t->socket))
                log_android(ANDROID_LOG_ERROR, "close error %d: %s", errno, strerror(errno));

            t->time = time(NULL);
            t->state = TCP_CLOSE;
        }

        // Cleanup lingering sessions
        if (t->state == TCP_CLOSE && t->time + TCP_KEEP_TIMEOUT < now) {
            if (tl == NULL)
                tcp_session = t->next;
            else
                tl->next = t->next;

            struct tcp_session *c = t;
            t = t->next;
            free(c);
        }
        else {
            tl = t;
            t = t->next;
        }
    }
}

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    // Initialize
    FD_ZERO(rfds);
    FD_ZERO(wfds);
    FD_ZERO(efds);

    // Always select tun
    FD_SET(args->tun, rfds);
    FD_SET(args->tun, efds);
    int max = args->tun;

    // Select UDP sockets
    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (!u->error) {
            FD_SET(u->socket, efds);
            FD_SET(u->socket, rfds);
            if (u->socket > max)
                max = u->socket;
        }
        u = u->next;
    }

    // Select TCP sockets
    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        // Select sockets
        if (t->state == TCP_LISTEN) {
            // Check for connected / errors
            FD_SET(t->socket, efds);
            FD_SET(t->socket, wfds);
            if (t->socket > max)
                max = t->socket;
        }
        else if (t->state == TCP_ESTABLISHED ||
                 t->state == TCP_SYN_RECV ||
                 t->state == TCP_CLOSE_WAIT) {
            // Check for data / errors
            FD_SET(t->socket, efds);
            if (t->send_window > 0)
                FD_SET(t->socket, rfds);
            if (t->socket > max)
                max = t->socket;
        }

        t = t->next;
    }

    return max;
}

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds,
              fd_set *efds) {
    // Check tun error
    if (FD_ISSET(args->tun, efds)) {
        log_android(ANDROID_LOG_ERROR, "tun exception");
        return -1; // over and out
    }

    // Check tun read
    if (FD_ISSET(args->tun, rfds)) {
        uint8_t buffer[TUN_MAXMSG];
        ssize_t length = read(args->tun, buffer, sizeof(buffer));
        if (length < 0) {
            log_android(ANDROID_LOG_ERROR, "tun read error %d: %s", errno, strerror(errno));
            return (errno == EINTR ? 0 : -1);
        }
        else if (length > 0) {
            // Write pcap record
            if (pcap_file != NULL)
                write_pcap_rec(buffer, (size_t) length);

            // Handle IP from tun
            handle_ip(args, buffer, (size_t) length);
        }
        else {
            // tun eof
            log_android(ANDROID_LOG_ERROR, "tun empty read");
            return -1;
        }
    }

    return 0;
}

void check_udp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct udp_session *cur = udp_session;
    while (cur != NULL) {
        // Check socket error
        if (FD_ISSET(cur->socket, efds)) {
            cur->time = time(NULL);

            int serr = 0;
            socklen_t optlen = sizeof(int);
            int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
            if (err < 0)
                log_android(ANDROID_LOG_ERROR, "UDP getsockopt error %d: %s",
                            errno, strerror(errno));
            else if (serr)
                log_android(ANDROID_LOG_ERROR, "UDP SO_ERROR %d: %s", serr, strerror(serr));

            cur->error = 1;
        }
        else {
            // Check socket read
            if (FD_ISSET(cur->socket, rfds)) {
                cur->time = time(NULL);

                uint8_t buffer[UDP4_MAXMSG];
                ssize_t bytes = recv(cur->socket, buffer, sizeof(buffer), 0);
                if (bytes < 0) {
                    // Socket error
                    log_android(ANDROID_LOG_ERROR, "UDP recv error %d: %s", errno, strerror(errno));

                    if (errno != EINTR)
                        cur->error = 1;
                }
                else if (bytes == 0) {
                    // Socket eof
                    log_android(ANDROID_LOG_WARN, "UDP recv empty");
                    cur->error = 1;

                } else {
                    // Socket read data
                    char dest[20];
                    inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
                    log_android(ANDROID_LOG_INFO, "UDP recv bytes %d for %s/%u @tun",
                                bytes, dest, ntohs(cur->dest));
                    if (write_udp(args, cur, buffer, (size_t) bytes, args->tun) < 0)
                        log_android(ANDROID_LOG_ERROR, "write UDP error %d: %s",
                                    errno, strerror((errno)));
                }
            }
        }

        cur = cur->next;
    }
}

void check_tcp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct tcp_session *cur = tcp_session;
    while (cur != NULL) {
        int oldstate = cur->state;
        uint32_t oldlocal = cur->local_seq;
        uint32_t oldremote = cur->remote_seq;

        // Check socket error
        if (FD_ISSET(cur->socket, efds)) {
            cur->time = time(NULL);

            int serr = 0;
            socklen_t optlen = sizeof(int);
            int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
            if (err < 0)
                log_android(ANDROID_LOG_ERROR, "getsockopt error %d: %s", errno, strerror(errno));
            else if (serr)
                log_android(ANDROID_LOG_ERROR, "SO_ERROR %d: %s", serr, strerror(serr));

            write_rst(args, cur, args->tun);
        }
        else {
            // Assume socket okay
            if (cur->state == TCP_LISTEN) {
                // Check socket connect
                if (FD_ISSET(cur->socket, wfds)) {
                    cur->time = time(NULL);

                    // Log
                    char source[20];
                    char dest[20];
                    inet_ntop(AF_INET, &(cur->saddr), source, sizeof(source));
                    inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
                    log_android(ANDROID_LOG_INFO, "Connected from %s/%u to %s/%u",
                                source, ntohs(cur->source), dest, ntohs(cur->dest));

                    if (write_syn_ack(args, cur, args->tun) >= 0) {
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
                if (FD_ISSET(cur->socket, rfds) && cur->send_window > 0) {
                    cur->time = time(NULL);

                    size_t len = (cur->send_window > TCP_SEND_WINDOW
                                  ? TCP_SEND_WINDOW
                                  : cur->send_window);
                    uint8_t *buffer = malloc(len);
                    ssize_t bytes = recv(cur->socket, buffer, len, 0);
                    if (bytes < 0) {
                        // Socket error
                        log_android(ANDROID_LOG_ERROR, "recv error %d: %s", errno, strerror(errno));

                        if (errno != EINTR)
                            write_rst(args, cur, args->tun);
                    }
                    else if (bytes == 0) {
                        // Socket eof
                        // TCP: application close
                        log_android(ANDROID_LOG_INFO, "recv empty state %s", strstate(cur->state));

                        if (write_fin_ack(args, cur, 0, args->tun) >= 0) {
                            cur->local_seq++; // local FIN

                            if (cur->state == TCP_SYN_RECV || cur->state == TCP_ESTABLISHED)
                                cur->state = TCP_FIN_WAIT1;
                            else if (cur->state == TCP_CLOSE_WAIT)
                                cur->state = TCP_LAST_ACK;
                            else
                                log_android(ANDROID_LOG_ERROR, "Unknown state %s",
                                            strstate(cur->state));

                            log_android(ANDROID_LOG_INFO, "Half close state %s",
                                        strstate(cur->state));
                        }
                    } else {
                        // Socket read data
                        log_android(ANDROID_LOG_DEBUG,
                                    "recv bytes %d state %s", bytes, strstate(cur->state));

                        // Forward to tun
                        if (write_data(args, cur, buffer, (size_t) bytes, args->tun) >= 0)
                            cur->local_seq += bytes;
                    }

                    free(buffer);
                }
            }
        }

        if (cur->state != oldstate || cur->local_seq != oldlocal ||
            cur->remote_seq != oldremote) {
            char dest[20];
            inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));
            log_android(ANDROID_LOG_INFO,
                        "Session %s/%u new state %s local %u remote %u",
                        dest, ntohs(cur->dest), strstate(cur->state),
                        cur->local_seq - cur->local_start,
                        cur->remote_seq - cur->remote_start);
        }

        cur = cur->next;
    }
}

void handle_ip(const struct arguments *args, const uint8_t *buffer, const size_t length) {
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
        struct iphdr *ip4hdr = (struct iphdr *) buffer;

        protocol = ip4hdr->protocol;
        saddr = &ip4hdr->saddr;
        daddr = &ip4hdr->daddr;

        if (ip4hdr->frag_off & IP_MF) {
            log_android(ANDROID_LOG_ERROR, "IP fragment");
            flags[flen++] = '+';
        }

        uint8_t ipoptlen = (uint8_t) ((ip4hdr->ihl - 5) * 4);
        payload = (uint8_t *) (buffer + sizeof(struct iphdr) + ipoptlen);

        if (ntohs(ip4hdr->tot_len) != length) {
            log_android(ANDROID_LOG_ERROR, "Invalid length %u header length %u",
                        length, ntohs(ip4hdr->tot_len));
            return;
        }

        if (loglevel < ANDROID_LOG_WARN) {
            if (!calc_checksum(0, (uint8_t *) ip4hdr, sizeof(struct iphdr))) {
                log_android(ANDROID_LOG_ERROR, "Invalid IP checksum");
                return;
            }
        }
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = (struct ip6_hdr *) buffer;

        protocol = ip6hdr->ip6_nxt;
        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;

        payload = (uint8_t *) (buffer + 40);

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
    jboolean syn = 0;
    int32_t sport = -1;
    int32_t dport = -1;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *) payload;

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
        struct udphdr *udp = (struct udphdr *) payload;

        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);

        // TODO checksum (IPv6)
    }
    flags[flen] = 0;

    // Get uid
    jint uid = -1;
    if ((protocol == IPPROTO_TCP && (!args->filter || syn)) || protocol == IPPROTO_UDP) {
        log_android(ANDROID_LOG_INFO, "get uid %s/%u syn %d", dest, dport, syn);
        int tries = 0;
        usleep(1000 * UID_DELAY);
        while (uid < 0 && tries++ < UID_MAXTRY) {
            // Check IPv6 table first
            int dump = (tries == UID_MAXTRY);
            if (version == 4) {
                int8_t saddr128[16];
                memset(saddr128, 0, 10);
                saddr128[10] = (uint8_t) 0xFF;
                saddr128[11] = (uint8_t) 0xFF;
                memcpy(saddr128 + 12, saddr, 4);
                uid = get_uid(protocol, 6, saddr128, (const uint16_t) sport, dump);
            }

            if (uid < 0)
                uid = get_uid(protocol, version, saddr, (const uint16_t) sport, dump);

            // Retry delay
            if (uid < 0 && tries < UID_MAXTRY) {
                log_android(ANDROID_LOG_WARN, "get uid %s/%u syn %d try %d",
                            dest, dport, syn, tries);
                usleep(1000 * UID_DELAYTRY);
            }
        }

        if (uid < 0)
            log_android(ANDROID_LOG_ERROR, "uid not found");
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

    // Check if allowed
    jboolean allowed = (jboolean) !syn;
    if (syn && args->filter && uid >= 0) {
        for (int i = 0; i < args->ucount; i++)
            if (args->uids[i] == uid) {
                allowed = 1;
                break;
            }
    }

    // Handle allowed traffic
    int log = 0;
    if (allowed) {
        if (protocol == IPPROTO_UDP)
            allowed = handle_udp(args, buffer, length, uid);
        else if (protocol == IPPROTO_TCP) {
            allowed = handle_tcp(args, buffer, length, uid);
            if (!allowed && loglevel < ANDROID_LOG_WARN)
                log = 1;
        }
        else
            allowed = 0;
    }

    // Log traffic
    if (args->log) {
        if (!args->filter || syn || log || protocol != IPPROTO_TCP)
            log_packet(args, version, protocol, flags, source, sport, dest, dport, uid, allowed);
    }
}

jboolean handle_udp(const struct arguments *args, const uint8_t *buffer, size_t length, int uid) {
    // Check version
    uint8_t version = (*buffer) >> 4;
    if (version != 4)
        return 0;

    // Get headers
    struct iphdr *iphdr = (struct iphdr *) buffer;
    uint8_t ipoptlen = (uint8_t) ((iphdr->ihl - 5) * 4);
    struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct iphdr) + ipoptlen);

    // Get data
    size_t dataoff = sizeof(struct iphdr) + ipoptlen + sizeof(struct udphdr);
    size_t datalen = length - dataoff;

    // Search session
    struct udp_session *last = NULL;
    struct udp_session *cur = udp_session;
    while (cur != NULL && !(cur->saddr == iphdr->saddr && cur->source == udphdr->source &&
                            cur->daddr == iphdr->daddr && cur->dest == udphdr->dest)) {
        last = cur;
        cur = cur->next;
    }

    char source[40];
    char dest[40];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, &(iphdr->saddr), source, sizeof(source));
    inet_ntop(version == 4 ? AF_INET : AF_INET6, &(iphdr->daddr), dest, sizeof(dest));

    // Create new session if needed
    if (cur == NULL) {
        log_android(ANDROID_LOG_WARN, "UDP new session from %s/%u to %s/%u",
                    source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));

        // Register session
        struct udp_session *u = malloc(sizeof(struct udp_session));
        u->uid = uid;
        u->version = 4;
        u->saddr = (__be32) iphdr->saddr;
        u->source = udphdr->source;
        u->daddr = (__be32) iphdr->daddr;
        u->dest = udphdr->dest;
        u->error = 0;
        u->next = NULL;

        // Open UDP socket
        u->socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (u->socket < 0) {
            log_android(ANDROID_LOG_ERROR, "UDP socket error %d: %s", errno, strerror(errno));
            u->error = 1;
            return 0;
        }
        else {
            // Check for broacast
            uint32_t broadcast = INADDR_BROADCAST;
            if (memcmp(&iphdr->daddr, &broadcast, sizeof(broadcast)) == 0) {
                log_android(ANDROID_LOG_WARN, "UDP broadcast");
                int on = 1;
                if (setsockopt(u->socket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
                    log_android(ANDROID_LOG_ERROR, "UDP setsockopt error %d: %s",
                                errno, strerror(errno));
            }

            protect_socket(args, u->socket);

            if (last == NULL)
                udp_session = u;
            else
                last->next = u;

            cur = u;
        }
    }

    // Check for DNS
    if (check_dns(args, cur, buffer, length))
        return 0;

    log_android(ANDROID_LOG_INFO, "UDP forward from tun %s/%u to %s/%u data %d",
                source, ntohs(udphdr->source), dest, ntohs(udphdr->dest), datalen);

    cur->time = time(NULL);

    struct sockaddr_in server;
    server.sin_family = (__kernel_sa_family_t) (version == 4 ? AF_INET : AF_INET6);
    server.sin_addr.s_addr = (__be32) iphdr->daddr;
    server.sin_port = udphdr->dest;

    if (sendto(cur->socket, buffer + dataoff, datalen, MSG_NOSIGNAL,
               (const struct sockaddr *) &server, sizeof(server)) != datalen) {
        log_android(ANDROID_LOG_ERROR, "UDP sendto error %s:%s", errno, strerror(errno));
        cur->error = 1;
        return 0;
    }

    return 1;
}

int check_dns(const struct arguments *args, const struct udp_session *u,
              const uint8_t *buffer, const size_t length) {
    // Get headers
    struct iphdr *iphdr = (struct iphdr *) buffer;
    uint8_t ipoptlen = (uint8_t) ((iphdr->ihl - 5) * 4);
    struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct iphdr) + ipoptlen);

    // Get data
    size_t dataoff = sizeof(struct iphdr) + ipoptlen + sizeof(struct udphdr);
    size_t datalen = length - dataoff;

    if (ntohs(udphdr->dest) == 53 && datalen > sizeof(struct dns_header)) {
        const struct dns_header *dns = (struct dns_header *) (buffer + dataoff);
        uint16_t flags = ntohs(dns->flags);

        // Check if standard query
        if ((flags & DNS_QR) == 0 && (flags & DNS_OPCODE) == 0 && dns->qdcount != 0) {
            char name[64];
            uint8_t noff = 0;

            // http://tools.ietf.org/html/rfc1035
            uint8_t len;
            size_t ptr;
            size_t qdoff = dataoff + sizeof(struct dns_header);
            do {
                len = *(buffer + qdoff);
                if (len <= 0x3F) {
                    ptr = qdoff;
                    qdoff += (1 + len);
                } else {
                    // TODO check top 2 bits
                    ptr = dataoff + (len & 0x3F) * 256 + *(buffer + qdoff + 1);
                    len = *(buffer + ptr);
                    qdoff += 2;
                }
                if (len && ptr + 1 + len <= dataoff + datalen) {
                    memcpy(name + noff, buffer + ptr + 1, len);
                    *(name + noff + len) = '.';
                    noff += (len + 1);
                }
            } while (len && ptr + 1 + len <= dataoff + datalen);

            if (noff > 0 && qdoff + 4 <= dataoff + datalen) {
                *(name + noff - 1) = 0;
                uint16_t qtype = ntohs(*((uint16_t *) (buffer + qdoff)));
                uint16_t qclass = ntohs(*((uint16_t *) (buffer + qdoff + 2)));
                qdoff += 4;

                if (qtype == DNS_QTYPE_A && qclass == DNS_QCLASS_IN)
                    for (int i = 0; i < args->hcount; i++)
                        if (!strcmp(name, args->hosts[i])) {
                            log_android(ANDROID_LOG_WARN, "DNS %s blocked", name);

                            struct dns_response reply;
                            reply.qname_ptr = htons(sizeof(struct dns_header) | 0xC000);
                            reply.qtype = htons(qtype);
                            reply.qclass = htons(qclass);
                            reply.ttl = htonl(DNS_TTL); // seconds
                            reply.rdlength = htons(sizeof(reply.rdata));
                            inet_aton("127.0.0.1", (struct in_addr *) &(reply.rdata));

                            size_t qsize = qdoff - dataoff;
                            size_t rsize = qsize + sizeof(struct dns_response);
                            uint8_t *response = malloc(rsize);
                            memcpy(response, buffer + dataoff, qsize);
                            memcpy(response + qsize, &reply, sizeof(struct dns_response));

                            struct dns_header *rh = (struct dns_header *) response;
                            rh->flags = htons(DNS_QR);
                            rh->ancount = htons(1);

                            if (write_udp(args, u, response, rsize, args->tun) < 0)
                                log_android(ANDROID_LOG_ERROR, "write UDP error %d: %s",
                                            errno, strerror((errno)));

                            return 1;
                        }
            }
        }
    }

    return 0;
}

jboolean handle_tcp(const struct arguments *args, const uint8_t *buffer, size_t length, int uid) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Check version
    uint8_t version = (*buffer) >> 4;
    if (version != 4)
        return 0;

    // Get headers
    struct iphdr *iphdr = (struct iphdr *) buffer;
    uint8_t ipoptlen = (uint8_t) ((iphdr->ihl - 5) * 4);
    struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct iphdr) + ipoptlen);
    uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    if (tcpoptlen)
        log_android(ANDROID_LOG_DEBUG, "optlen %d", tcpoptlen);

    // Get data
    size_t dataoff = sizeof(struct iphdr) + ipoptlen + sizeof(struct tcphdr) + tcpoptlen;
    size_t datalen = length - dataoff;

    // Search session
    struct tcp_session *last = NULL;
    struct tcp_session *cur = tcp_session;
    while (cur != NULL && !(cur->saddr == iphdr->saddr && cur->source == tcphdr->source &&
                            cur->daddr == iphdr->daddr && cur->dest == tcphdr->dest)) {
        last = cur;
        cur = cur->next;
    }

    // Log
    char source[20];
    char dest[20];
    inet_ntop(AF_INET, &(iphdr->saddr), source, sizeof(source));
    inet_ntop(AF_INET, &(iphdr->daddr), dest, sizeof(dest));

    log_android(ANDROID_LOG_DEBUG, "Received from %s/%u for %s/%u seq %u ack %u window %u data %d",
                source, ntohs(tcphdr->source),
                dest, ntohs(tcphdr->dest),
                ntohl(tcphdr->seq) - (cur == NULL ? 0 : cur->remote_start),
                ntohl(tcphdr->ack_seq) - (cur == NULL ? 0 : cur->local_start),
                ntohs(tcphdr->window), datalen);

    if (cur == NULL) {
        if (tcphdr->syn) {
            log_android(ANDROID_LOG_INFO, "New session from %s/%u to %s/%u window %u uid %d",
                        source, ntohs(tcphdr->source),
                        dest, ntohs(tcphdr->dest),
                        ntohs(tcphdr->window), uid);

            // Register session
            struct tcp_session *syn = malloc(sizeof(struct tcp_session));
            syn->time = time(NULL);
            syn->uid = uid;
            syn->version = 4;
            syn->send_window = ntohs(tcphdr->window);
            syn->remote_seq = ntohl(tcphdr->seq); // ISN remote
            syn->local_seq = (uint32_t) rand(); // ISN local
            syn->remote_start = syn->remote_seq;
            syn->local_start = syn->local_seq;
            syn->saddr = (__be32) iphdr->saddr;
            syn->source = tcphdr->source;
            syn->daddr = (__be32) iphdr->daddr;
            syn->dest = tcphdr->dest;
            syn->state = TCP_LISTEN;
            syn->next = NULL;

            // TODO handle SYN data?
            if (datalen)
                log_android(ANDROID_LOG_WARN, "SYN session from %s/%u to %s/%u data %u",
                            source, ntohs(tcphdr->source),
                            dest, ntohs(tcphdr->dest), datalen);

            // Open socket
            syn->socket = open_socket(syn, args);
            if (syn->socket < 0) {
                syn->state = TCP_TIME_WAIT;
                // Remote might retry
                free(syn);
                return 0;
            }
            else {
                int32_t lport = get_local_port(syn->socket);
                log_android(ANDROID_LOG_INFO, "Open from %s/%u to %s/%u socket %d lport %u ",
                            source, ntohs(tcphdr->source), dest, ntohs(tcphdr->dest),
                            syn->socket, lport);

                if (last == NULL)
                    tcp_session = syn;
                else
                    last->next = syn;
            }
        }
        else {
            log_android(ANDROID_LOG_WARN, "Unknown session from %s/%u to %s/%u uid %d",
                        source, ntohs(tcphdr->source),
                        dest, ntohs(tcphdr->dest), uid);

            struct tcp_session rst;
            memset(&rst, 0, sizeof(struct tcp_session));
            rst.version = 4;
            rst.local_seq = 0;
            rst.remote_seq = ntohl(tcphdr->seq);
            rst.saddr = (__be32) iphdr->saddr;
            rst.source = tcphdr->source;
            rst.daddr = (__be32) iphdr->daddr;
            rst.dest = tcphdr->dest;
            write_rst(args, &rst, args->tun);

            return 0;
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
        if (cur->state == TCP_CLOSE) {
            log_android(ANDROID_LOG_WARN,
                        "Closed session from %s/%u to %s/%u state %s local %u remote %u",
                        source, ntohs(tcphdr->source),
                        dest, ntohs(cur->dest), strstate(cur->state),
                        cur->local_seq - cur->local_start,
                        cur->remote_seq - cur->remote_start);
            write_rst(args, cur, args->tun);
            return 0;
        }
        else {
            int oldstate = cur->state;
            uint32_t oldlocal = cur->local_seq;
            uint32_t oldremote = cur->remote_seq;

            log_android(ANDROID_LOG_DEBUG,
                        "Session from %s/%u to %s/%u state %s local %u remote %u window %u",
                        source, ntohs(tcphdr->source),
                        dest, ntohs(cur->dest), strstate(cur->state),
                        cur->local_seq - cur->local_start,
                        cur->remote_seq - cur->remote_start,
                        ntohs(tcphdr->window));

            cur->time = time(NULL);
            cur->send_window = ntohs(tcphdr->window);

            // Do not change order of conditions

            // Forward data to socket
            int ok = 1;
            if (ntohl(tcphdr->seq) == cur->remote_seq && datalen) {
                log_android(ANDROID_LOG_DEBUG, "send socket data %u", datalen);

                int more = (tcphdr->psh ? 0 : MSG_MORE);
                if (send(cur->socket, buffer + dataoff, datalen, MSG_NOSIGNAL | more) < 0) {
                    log_android(ANDROID_LOG_ERROR, "send error %d: %s", errno, strerror(errno));
                    write_rst(args, cur, args->tun);
                    return 0;
                }

                if (tcphdr->fin ||
                    cur->state == TCP_FIN_WAIT1 ||
                    cur->state == TCP_FIN_WAIT2 ||
                    cur->state == TCP_CLOSING)
                    cur->remote_seq += datalen; // FIN will send ACK or no ACK
                else {
                    if (write_ack(args, cur, datalen, args->tun) >= 0)
                        cur->remote_seq += datalen;
                    else
                        ok = 0;
                }
            }

            if (ok) {
                if (tcphdr->rst) {
                    // No sequence check
                    log_android(ANDROID_LOG_INFO, "Received RST from %s/%u to %s/%u state %s",
                                source, ntohs(tcphdr->source), dest, ntohs(cur->dest),
                                strstate(cur->state));
                    cur->state = TCP_TIME_WAIT;
                    return 0;
                }
                else {
                    if (ntohl(tcphdr->ack_seq) == cur->local_seq &&
                        ntohl(tcphdr->seq) == cur->remote_seq) {

                        if (tcphdr->syn) {
                            log_android(ANDROID_LOG_WARN,
                                        "Repeated SYN from %s/%u to %s/%u state %s",
                                        source, ntohs(tcphdr->source), dest, ntohs(cur->dest),
                                        strstate(cur->state));
                            // The socket is likely not opened yet
                            // Note: perfect, ordered packet receive assumed

                        } else if (tcphdr->fin /* ACK */) {
                            // Shutdown socket for writing
                            if (shutdown(cur->socket, SHUT_WR)) {
                                log_android(ANDROID_LOG_ERROR, "shutdown WR error %d: %s",
                                            errno, strerror(errno));
                                // Data might be lost
                                write_rst(args, cur, args->tun);
                                return 0;
                            }
                            else {
                                if (write_ack(args, cur, 1, args->tun) >= 0) {
                                    cur->remote_seq += 1; // FIN
                                    if (cur->state == TCP_ESTABLISHED /* && !tcphdr->ack */)
                                        cur->state = TCP_CLOSE_WAIT;
                                    else if (cur->state == TCP_FIN_WAIT1 && tcphdr->ack)
                                        cur->state = TCP_TIME_WAIT;
                                    else if (cur->state == TCP_FIN_WAIT1 && !tcphdr->ack)
                                        cur->state = TCP_CLOSING;
                                    else if (cur->state == TCP_FIN_WAIT2 /* && !tcphdr->ack */)
                                        cur->state = TCP_TIME_WAIT;
                                    else {
                                        log_android(ANDROID_LOG_ERROR,
                                                    "Invalid FIN from %s/%u to %s/%u state %s ACK %d",
                                                    source, ntohs(tcphdr->source),
                                                    dest, ntohs(cur->dest),
                                                    strstate(cur->state), tcphdr->ack);
                                        return 0;
                                    }
                                }
                                else {
                                    write_rst(args, cur, args->tun);
                                    return 0;
                                }
                            }
                        }

                        else if (tcphdr->ack) {
                            if (cur->state == TCP_SYN_RECV)
                                cur->state = TCP_ESTABLISHED;
                            else if (cur->state == TCP_ESTABLISHED) {
                                log_android(ANDROID_LOG_DEBUG,
                                            "New ACK from %s/%u to %s/%u state %s data %u",
                                            source, ntohs(tcphdr->source), dest, ntohs(cur->dest),
                                            strstate(cur->state), datalen);
                            }
                            else if (cur->state == TCP_LAST_ACK) {
                                // socket has been shutdown already
                                cur->state = TCP_TIME_WAIT;
                            }
                            else if (cur->state == TCP_FIN_WAIT1)
                                cur->state = TCP_FIN_WAIT2;
                            else if (cur->state == TCP_CLOSING)
                                cur->state = TCP_TIME_WAIT;
                            else {
                                log_android(ANDROID_LOG_ERROR,
                                            "Invalid ACK from %s/%u to %s/%u state %s",
                                            source, ntohs(tcphdr->source), dest, ntohs(cur->dest),
                                            strstate(cur->state));
                                return 0;
                            }
                        }

                        else {
                            log_android(ANDROID_LOG_ERROR,
                                        "Unknown packet from %s/%u to %s/%u state %s",
                                        source, ntohs(tcphdr->source), dest, ntohs(cur->dest),
                                        strstate(cur->state));
                            return 0;
                        }
                    }
                    else {
                        char *msg;
                        static char previous[] = "Previous";
                        static char repeated[] = "Repeated";
                        static char invalid[] = "Invalid";
                        static char keepalive[] = "Keep alive";

                        // TODO proper wrap around
                        jboolean allowed = 1;
                        if (tcphdr->ack && ((uint32_t) ntohl(tcphdr->seq) + 1) == cur->remote_seq)
                            msg = keepalive;
                        else if (ntohl(tcphdr->seq) == cur->remote_seq &&
                                 ntohl(tcphdr->ack_seq) < cur->local_seq)
                            msg = previous;
                        else if (ntohl(tcphdr->seq) < cur->remote_seq &&
                                 ntohl(tcphdr->ack_seq) == cur->local_seq)
                            msg = repeated;
                        else {
                            msg = invalid;
                            allowed = 0;
                        }

                        char flags[10];
                        int flen = 0;
                        if (tcphdr->syn)
                            flags[flen++] = 'S';
                        if (tcphdr->ack)
                            flags[flen++] = 'A';
                        if (tcphdr->fin)
                            flags[flen++] = 'F';
                        flags[flen] = 0;

                        log_android(tcphdr->fin ? ANDROID_LOG_WARN : ANDROID_LOG_INFO,
                                    "%s %s from %s/%u to %s/%u state %s seq %u/%u ack %u/%u data %d",
                                    msg, flags,
                                    source, ntohs(tcphdr->source),
                                    dest, ntohs(cur->dest),
                                    strstate(cur->state),
                                    ntohl(tcphdr->seq) - cur->remote_start,
                                    cur->remote_seq - cur->remote_start,
                                    ntohl(tcphdr->ack_seq) - cur->local_start,
                                    cur->local_seq - cur->local_start,
                                    datalen);

                        return allowed;
                    }
                }
            }

            if (cur->state != oldstate || cur->local_seq != oldlocal ||
                cur->remote_seq != oldremote)
                log_android(ANDROID_LOG_INFO,
                            "Session from %s/%u to %s/%u new state %s local %u remote %u window %u",
                            source, ntohs(tcphdr->source),
                            dest, ntohs(cur->dest),
                            strstate(cur->state),
                            cur->local_seq - cur->local_start,
                            cur->remote_seq - cur->remote_start,
                            ntohs(tcphdr->window));
        }

#ifdef PROFILE
        gettimeofday(&end, NULL);
        mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                    (end.tv_usec - start.tv_usec) / 1000.0;
        if (mselapsed > 1)
            log_android(ANDROID_LOG_INFO, "existing session %f", mselapsed);
#endif
    }

    return 1;
}

int open_socket(const struct tcp_session *cur, const struct arguments *args) {
    int sock;

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
    if (protect_socket(args, sock) < 0)
        return -1;

    // Set non blocking
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_android(ANDROID_LOG_ERROR, "fcntl socket O_NONBLOCK error %d: %s",
                    errno, strerror(errno));
        return -1;
    }

    // Initiate connect
    int err = connect(sock, (const struct sockaddr *) &daddr, sizeof(struct sockaddr_in));
    if (err < 0 && errno != EINPROGRESS) {
        log_android(ANDROID_LOG_ERROR, "connect error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Set blocking
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        log_android(ANDROID_LOG_ERROR, "fcntl socket ~O_NONBLOCK error %d: %s",
                    errno, strerror(errno));
        return -1;
    }

    return sock;
}

int32_t get_local_port(const int sock) {
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sock, (struct sockaddr *) &sin, &len) < 0) {
        log_android(ANDROID_LOG_ERROR, "getsockname error %d: %s", errno, strerror(errno));
        return -1;
    } else
        return ntohs(sin.sin_port);
}

int write_syn_ack(const struct arguments *args, struct tcp_session *cur, int tun) {
    if (write_tcp(args, cur, NULL, 0, 1, 1, 1, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write SYN+ACK error %d: %s",
                    errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

int write_ack(const struct arguments *args, struct tcp_session *cur, size_t bytes, int tun) {
    if (write_tcp(args, cur, NULL, 0, bytes, 0, 1, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write ACK error %d: %s",
                    errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length, int tun) {
    if (write_tcp(args, cur, buffer, length, 0, 0, 1, 0, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write data ACK error %d: %s", errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

int write_fin_ack(const struct arguments *args, struct tcp_session *cur, size_t bytes, int tun) {
    if (write_tcp(args, cur, NULL, 0, bytes, 0, 1, 1, 0, tun) < 0) {
        log_android(ANDROID_LOG_ERROR, "write FIN+ACK error %d: %s", errno, strerror((errno)));
        cur->state = TCP_TIME_WAIT;
        return -1;
    }
    return 0;
}

void write_rst(const struct arguments *args, struct tcp_session *cur, int tun) {
    log_android(ANDROID_LOG_WARN, "Sending RST");
    if (write_tcp(args, cur, NULL, 0, 0, 0, 0, 0, 1, tun) < 0)
        log_android(ANDROID_LOG_ERROR, "write RST error %d: %s", errno, strerror((errno)));
    cur->state = TCP_TIME_WAIT;
}

ssize_t write_udp(const struct arguments *args, const struct udp_session *cur,
                  uint8_t *data, size_t datalen, int tun) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Build packet
    size_t len = sizeof(struct iphdr) + sizeof(struct udphdr) + datalen;
    u_int8_t *buffer = calloc(len, 1);
    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    if (datalen)
        memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), data, datalen);

    // Build IP header
    ip->version = 4;
    ip->ihl = sizeof(struct iphdr) >> 2;
    ip->tot_len = htons(len);
    ip->ttl = UDP_TTL;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = cur->daddr;
    ip->daddr = cur->saddr;

    // Calculate IP checksum
    ip->check = ~calc_checksum(0, (uint8_t *) ip, sizeof(struct iphdr));

    // Build TCP header
    udp->source = cur->dest;
    udp->dest = cur->source;
    udp->check = 0;
    udp->len = htons(sizeof(struct udphdr) + datalen);

    char source[20];
    char dest[20];
    inet_ntop(AF_INET, &(ip->saddr), source, sizeof(source));
    inet_ntop(AF_INET, &(ip->daddr), dest, sizeof(dest));

    // Send packet
    log_android(ANDROID_LOG_DEBUG,
                "Sending UDP to tun from %s/%u to %s/%u data %u",
                source, ntohs(udp->source), dest, ntohs(udp->dest), datalen);

    ssize_t res = write(tun, buffer, len);

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "tun UDP write %f", mselapsed);
#endif

    if (args->log)
        log_packet(args, cur->version, ip->protocol, "",
                   source, ntohs(udp->source), dest, ntohs(udp->dest), cur->uid, 1);

    // Write pcap record
    if (pcap_file != NULL)
        write_pcap_rec(buffer, len);

    free(buffer);

    return res;
}


ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen, size_t confirm,
                  int syn, int ack, int fin, int rst, int tun) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Build packet
    size_t len = sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen;
    u_int8_t *buffer = calloc(len, 1);
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    if (datalen)
        memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr), data, datalen);

    // Build IP header
    ip->version = 4;
    ip->ihl = sizeof(struct iphdr) >> 2;
    ip->tot_len = htons(len);
    ip->ttl = TCP_TTL;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = cur->daddr;
    ip->daddr = cur->saddr;

    // Calculate IP checksum
    ip->check = ~calc_checksum(0, (uint8_t *) ip, sizeof(struct iphdr));

    // Build TCP header
    tcp->source = cur->dest;
    tcp->dest = cur->source;
    tcp->seq = htonl(cur->local_seq);
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq + confirm));
    tcp->doff = sizeof(struct tcphdr) >> 2;
    tcp->syn = (__u16) syn;
    tcp->ack = (__u16) ack;
    tcp->fin = (__u16) fin;
    tcp->rst = (__u16) rst;
    tcp->window = htons(TCP_RECV_WINDOW);

    if (!tcp->ack)
        tcp->ack_seq = 0;

    // Calculate TCP checksum
    struct ippseudo pseudo;
    pseudo.ippseudo_src.s_addr = (__be32) ip->saddr;
    pseudo.ippseudo_dst.s_addr = (__be32) ip->daddr;
    pseudo.ippseudo_pad = 0;
    pseudo.ippseudo_p = ip->protocol;
    pseudo.ippseudo_len = htons(sizeof(struct tcphdr) + datalen);

    uint16_t csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    csum = calc_checksum(csum, (uint8_t *) tcp, sizeof(struct tcphdr));
    csum = calc_checksum(csum, (uint8_t *) data, datalen);

    tcp->check = ~csum;

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

    ssize_t res = write(tun, buffer, len);

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "tun TCP write %f", mselapsed);
#endif

    // Write pcap record
    if (pcap_file != NULL)
        write_pcap_rec(buffer, len);

    free(buffer);

    return res;
}

uint8_t char2nible(const char c) {
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t) ((c - 'a') + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t) ((c - 'A') + 10);
    return 255;
}

void hex2bytes(const char *hex, uint8_t *buffer) {
    size_t len = strlen(hex);
    for (int i = 0; i < len; i += 2)
        buffer[i / 2] = (char2nible(hex[i]) << 4) | char2nible(hex[i + 1]);
}

jint get_uid(const int protocol, const int version,
             const void *saddr, const uint16_t sport, int dump) {
    char line[250];
    char hex[16 * 2 + 1];
    int fields;
    uint8_t addr4[4];
    uint8_t addr6[16];
    int port;
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

    if (dump) {
        char source[40];
        inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
        log_android(ANDROID_LOG_INFO, "Searching %s/%u in %s", source, sport, fn);
    }

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
                        "%*d: %8s:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld",
                        hex, &port, &u);
            else
                fields = sscanf(
                        line,
                        "%*d: %32s:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld",
                        hex, &port, &u);
            if (fields == 3) {
                hex2bytes(hex, version == 4 ? addr4 : addr6);
                if (version == 4)
                    ((uint32_t *) addr4)[0] = htonl(((uint32_t *) addr4)[0]);
                for (int w = 0; w < 4; w++)
                    ((uint32_t *) addr6)[w] = htonl(((uint32_t *) addr6)[w]);

                if (dump) {
                    char source[40];
                    inet_ntop(version == 4 ? AF_INET : AF_INET6,
                              version == 4 ? addr4 : addr6,
                              source, sizeof(source));
                    log_android(ANDROID_LOG_INFO, "%s/%u %d", source, sport, u);
                }

                if (port == sport) {
                    if (memcmp(version == 4 ? addr4 : addr6, saddr, version == 4 ? 4 : 16) ==
                        0) {
                        uid = u;
                        break;
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

int protect_socket(const struct arguments *args, int socket) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    jmethodID mid = jniGetMethodID(args->env, cls, "protect", "(I)Z");

    jboolean isProtected = (*args->env)->CallBooleanMethod(args->env, args->instance, mid, socket);
    jniCheckException(args->env);

    if (!isProtected) {
        log_android(ANDROID_LOG_ERROR, "protect socket failed");
        return -1;
    }

    (*args->env)->DeleteLocalRef(args->env, cls);

    return 0;
}

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, size_t length) {
    register uint32_t sum = start;
    register uint16_t *buf = (uint16_t *) buffer;
    register size_t len = length;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len > 0)
        sum += *((uint8_t *) buf);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) sum;
}

// http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html
// http://journals.ecs.soton.ac.uk/java/tutorial/native1.1/implementing/index.html

jobject jniGlobalRef(JNIEnv *env, jobject cls) {
    jobject gcls = (*env)->NewGlobalRef(env, cls);
    if (gcls == NULL)
        log_android(ANDROID_LOG_ERROR, "Global ref failed (out of memory?)");
    return gcls;
}

jclass jniFindClass(JNIEnv *env, const char *name) {
    jclass cls = (*env)->FindClass(env, name);
    if (cls == NULL)
        log_android(ANDROID_LOG_ERROR, "Class %s not found", name);
    else
        jniCheckException(env);
    return cls;
}

jmethodID method_protect = NULL;
jmethodID method_logPacket = NULL;

jmethodID jniGetMethodID(JNIEnv *env, jclass cls, const char *name, const char *signature) {
    if (strcmp(name, "protect") == 0 && method_protect != NULL)
        return method_protect;
    if (strcmp(name, "logPacket") == 0 && method_logPacket != NULL)
        return method_logPacket;

    jmethodID method = (*env)->GetMethodID(env, cls, name, signature);
    if (method == NULL)
        log_android(ANDROID_LOG_ERROR, "Method %s%s", name, signature);
    else {
        if (strcmp(name, "protect") == 0) {
            method_protect = method;
            log_android(ANDROID_LOG_INFO, "Cached method ID protect");
        }
        else if (strcmp(name, "logPacket") == 0) {
            method_logPacket = method;
            log_android(ANDROID_LOG_INFO, "Cached method ID logPacket");
        }
    }
    return method;
}

jfieldID jniGetFieldID(JNIEnv *env, jclass cls, const char *name, const char *type) {
    jfieldID field = (*env)->GetFieldID(env, cls, name, type);
    if (field == NULL)
        log_android(ANDROID_LOG_ERROR, "Field %s type %s not found", name, type);
    return field;
}

jobject jniNewObject(JNIEnv *env, jclass cls, jmethodID constructor, const char *name) {
    jobject object = (*env)->NewObject(env, cls, constructor);
    if (object == NULL)
        log_android(ANDROID_LOG_ERROR, "Create object %s failed", name);
    else
        jniCheckException(env);
    return object;
}

int jniCheckException(JNIEnv *env) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    if (ex) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, ex);
        return 1;
    }
    return 0;
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

void log_packet(
        const struct arguments *args,
        jint version,
        jint protocol,
        const char *flags,
        const char *source,
        jint sport,
        const char *dest,
        jint dport,
        jint uid,
        jboolean allowed) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    JNIEnv *env = args->env;
    jclass clsService = (*env)->GetObjectClass(env, args->instance);

    const char *signature = "(Leu/faircode/netguard/Packet;)V";
    jmethodID logPacket = jniGetMethodID(env, clsService, "logPacket", signature);

    const char *packet = "eu/faircode/netguard/Packet";
    jmethodID initPacket = jniGetMethodID(env, clsPacket, "<init>", "()V");
    jobject objPacket = jniNewObject(env, clsPacket, initPacket, packet);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    jlong t = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    jstring jflags = (*env)->NewStringUTF(env, flags);
    jstring jsource = (*env)->NewStringUTF(env, source);
    jstring jdest = (*env)->NewStringUTF(env, dest);

    const char *string = "Ljava/lang/String;";
    (*env)->SetLongField(env, objPacket, jniGetFieldID(env, clsPacket, "time", "J"), t);
    (*env)->SetIntField(env, objPacket, jniGetFieldID(env, clsPacket, "version", "I"), version);
    (*env)->SetIntField(env, objPacket, jniGetFieldID(env, clsPacket, "protocol", "I"), protocol);
    (*env)->SetObjectField(env, objPacket, jniGetFieldID(env, clsPacket, "flags", string), jflags);
    (*env)->SetObjectField(env, objPacket, jniGetFieldID(env, clsPacket, "saddr", string), jsource);
    (*env)->SetIntField(env, objPacket, jniGetFieldID(env, clsPacket, "sport", "I"), sport);
    (*env)->SetObjectField(env, objPacket, jniGetFieldID(env, clsPacket, "daddr", string), jdest);
    (*env)->SetIntField(env, objPacket, jniGetFieldID(env, clsPacket, "dport", "I"), dport);
    (*env)->SetIntField(env, objPacket, jniGetFieldID(env, clsPacket, "uid", "I"), uid);
    (*env)->SetBooleanField(env, objPacket, jniGetFieldID(env, clsPacket, "allowed", "Z"), allowed);

    (*env)->CallVoidMethod(env, args->instance, logPacket, objPacket);
    jniCheckException(env);

    (*env)->DeleteLocalRef(env, jdest);
    (*env)->DeleteLocalRef(env, jsource);
    (*env)->DeleteLocalRef(env, jflags);
    (*env)->DeleteLocalRef(env, objPacket);
    (*env)->DeleteLocalRef(env, clsService);

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "log java %f", mselapsed);
#endif
}

void write_pcap_hdr() {
    struct pcap_hdr_s pcap_hdr;
    pcap_hdr.magic_number = 0xa1b2c3d4;
    pcap_hdr.version_major = 2;
    pcap_hdr.version_minor = 4;
    pcap_hdr.thiszone = 0;
    pcap_hdr.sigfigs = 0;
    pcap_hdr.snaplen = MAX_PCAP_RECORD;
    pcap_hdr.network = LINKTYPE_RAW;
    write_pcap(&pcap_hdr, sizeof(struct pcap_hdr_s));
}

void write_pcap_rec(const uint8_t *buffer, size_t length) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts))
        log_android(ANDROID_LOG_ERROR, "clock_gettime error %d: %s", errno, strerror(errno));

    size_t plen = (length < MAX_PCAP_RECORD ? length : MAX_PCAP_RECORD);
    struct pcaprec_hdr_s pcap_rec;

    pcap_rec.ts_sec = (guint32_t) ts.tv_sec;
    pcap_rec.ts_usec = (guint32_t) (ts.tv_nsec / 1000);
    pcap_rec.incl_len = (guint32_t) plen;
    pcap_rec.orig_len = (guint32_t) length;

    write_pcap(&pcap_rec, sizeof(struct pcaprec_hdr_s));
    write_pcap(buffer, plen);
}

void write_pcap(const void *ptr, size_t len) {
#ifdef PROFILE
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    if (fwrite(ptr, len, 1, pcap_file) < 1)
        log_android(ANDROID_LOG_ERROR, "PCAP fwrite error %d: %s", errno, strerror(errno));
    else {
        long fsize = ftell(pcap_file);
        log_android(ANDROID_LOG_DEBUG, "PCAP wrote %d @%ld", len, fsize);

        if (fsize > MAX_PCAP_FILE) {
            log_android(ANDROID_LOG_INFO, "PCAP truncate @%ld", fsize);
            if (ftruncate(fileno(pcap_file), sizeof(struct pcap_hdr_s)))
                log_android(ANDROID_LOG_ERROR, "PCAP ftruncate error %d: %s",
                            errno, strerror(errno));
            else {
                if (!lseek(fileno(pcap_file), sizeof(struct pcap_hdr_s), SEEK_SET))
                    log_android(ANDROID_LOG_ERROR, "PCAP ftruncate error %d: %s",
                                errno, strerror(errno));
            }
        }
    }

#ifdef PROFILE
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > 1)
        log_android(ANDROID_LOG_INFO, "pcap write %f", mselapsed);
#endif
}

char *trim(char *str) {
    while (isspace(*str))
        str++;
    if (*str == 0)
        return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;
    *(end + 1) = 0;
    return str;
}

void read_hosts(const char *name, struct arguments *args) {
    log_android(ANDROID_LOG_INFO, "Reading %s", name);

    args->hcount = 0;
    args->hosts = NULL;

    FILE *hosts;
    if ((hosts = fopen(name, "r")) == NULL) {
        log_android(ANDROID_LOG_ERROR, "fopen(%s) error %d: %s", name, errno, strerror(errno));
        return;
    }

    char buffer[160];
    while (fgets(buffer, sizeof(buffer), hosts)) {
        char *hash = strchr(buffer, '#');
        if (hash)
            *hash = 0;

        char *host = trim(buffer);
        while (*host && !isspace(*host))
            host++;

        if (isspace(*host)) {
            host++;
            if (*host && strcmp(host, "localhost")) {
                args->hosts = realloc(args->hosts, sizeof(char *) * (args->hcount + 1));
                args->hosts[args->hcount] = malloc(strlen(host) + 1);
                strcpy(args->hosts[args->hcount], host);
                args->hcount++;
            }
        }
    }

    if (fclose(hosts))
        log_android(ANDROID_LOG_ERROR, "fclose(%s) error %d: %s", name, errno, strerror(errno));

    for (int i = 0; i < args->hcount; i++)
        log_android(ANDROID_LOG_DEBUG, "host '%s'", args->hosts[i]);
}

const char *strstate(const int state) {
    switch (state) {
        case TCP_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_SYN_SENT:
            return "SYN_SENT";
        case TCP_SYN_RECV:
            return "SYN_RECV";
        case TCP_FIN_WAIT1:
            return "FIN_WAIT1";
        case TCP_FIN_WAIT2:
            return "FIN_WAIT2";
        case TCP_TIME_WAIT:
            return "TIME_WAIT";
        case TCP_CLOSE:
            return "CLOSE";
        case TCP_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_LAST_ACK:
            return "LAST_ACK";
        case TCP_LISTEN:
            return "LISTEN";
        case  TCP_CLOSING:
            return "CLOSING";
        default:
            return "UNKNOWN";
    }
}

char *hex(const u_int8_t *data, const size_t len) {
    char hex_str[] = "0123456789ABCDEF";

    char *hexout;
    hexout = (char *) malloc(len * 3 + 1); // TODO free

    for (size_t i = 0; i < len; i++) {
        hexout[i * 3 + 0] = hex_str[(data[i] >> 4) & 0x0F];
        hexout[i * 3 + 1] = hex_str[(data[i]) & 0x0F];
        hexout[i * 3 + 2] = ' ';
    }
    hexout[len * 3] = 0;

    return hexout;
}
