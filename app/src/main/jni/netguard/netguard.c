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
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "netguard.h"

// #define PROFILE_EVENTS 5
// #define PROFILE_UID 5
// #define PROFILE_JNI 5

// TODO TCP options
// TODO TCP fragmentation

// It is assumed that no packets will get lost and that packets arrive in order

// Global variables

static JavaVM *jvm = NULL;
static pthread_t thread_id = 0;
static pthread_mutex_t lock;
static jboolean stopping = 0;
static jboolean signaled = 0;

static struct icmp_session *icmp_session = NULL;
static struct udp_session *udp_session = NULL;
static struct tcp_session *tcp_session = NULL;

static int loglevel = 0;
static FILE *pcap_file = NULL;

static int max_tun_msg = 0;

// JNI

jclass clsPacket;
jclass clsAllowed;
jclass clsRR;

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI load");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
        return -1;
    }

    const char *packet = "eu/faircode/netguard/Packet";
    clsPacket = jniGlobalRef(env, jniFindClass(env, packet));

    const char *allowed = "eu/faircode/netguard/Allowed";
    clsAllowed = jniGlobalRef(env, jniFindClass(env, allowed));

    const char *rr = "eu/faircode/netguard/ResourceRecord";
    clsRR = jniGlobalRef(env, jniFindClass(env, rr));

    return JNI_VERSION_1_6;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI unload");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK)
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
    else {
        (*env)->DeleteGlobalRef(env, clsPacket);
        (*env)->DeleteGlobalRef(env, clsRR);
    }
}

// JNI SinkholeService

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env) {
    icmp_session = NULL;
    udp_session = NULL;
    tcp_session = NULL;
    loglevel = ANDROID_LOG_WARN;
    pcap_file = NULL;

    if (pthread_mutex_init(&lock, NULL))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_init failed");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1start(
        JNIEnv *env, jobject instance, jint tun, jboolean fwd53, jint loglevel_) {

    loglevel = loglevel_;
    max_tun_msg = 0;
    log_android(ANDROID_LOG_WARN,
                "Starting tun %d fwd53 %d level %d thread %x",
                tun, fwd53, loglevel, thread_id);

    // Set blocking
    int flags = fcntl(tun, F_GETFL, 0);
    if (flags < 0 || fcntl(tun, F_SETFL, flags & ~O_NONBLOCK) < 0)
        log_android(ANDROID_LOG_ERROR, "fcntl tun ~O_NONBLOCK error %d: %s",
                    errno, strerror(errno));

    if (thread_id && pthread_kill(thread_id, 0) == 0)
        log_android(ANDROID_LOG_ERROR, "Already running thread %x", thread_id);
    else {
        jint rs = (*env)->GetJavaVM(env, &jvm);
        if (rs != JNI_OK)
            log_android(ANDROID_LOG_ERROR, "GetJavaVM failed");

        // Get arguments
        struct arguments *args = malloc(sizeof(struct arguments));
        // args->env = will be set in thread
        args->instance = (*env)->NewGlobalRef(env, instance);
        args->tun = tun;
        args->fwd53 = fwd53;

        // Start native thread
        int err = pthread_create(&thread_id, NULL, handle_events, (void *) args);
        if (err == 0)
            log_android(ANDROID_LOG_WARN, "Started thread %x", thread_id);
        else
            log_android(ANDROID_LOG_ERROR, "pthread_create error %d: %s", err, strerror(err));
    }
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1stop(
        JNIEnv *env, jobject instance, jint tun, jboolean clear) {
    pthread_t t = thread_id;
    log_android(ANDROID_LOG_WARN, "Stop tun %d clear %d thread %x", tun, (int) clear, t);
    if (t && pthread_kill(t, 0) == 0) {
        stopping = 1;
        log_android(ANDROID_LOG_WARN, "Kill thread %x", t);
        int err = pthread_kill(t, SIGUSR1);
        if (err != 0)
            log_android(ANDROID_LOG_WARN, "pthread_kill error %d: %s", err, strerror(err));
        else {
            log_android(ANDROID_LOG_WARN, "Join thread %x", t);
            err = pthread_join(t, NULL);
            if (err != 0)
                log_android(ANDROID_LOG_WARN, "pthread_join error %d: %s", err, strerror(err));
        }

        if (clear)
            clear_sessions();

        log_android(ANDROID_LOG_WARN, "Stopped thread %x", t);
    } else
        log_android(ANDROID_LOG_WARN, "Not running thread %x", t);
}

JNIEXPORT jintArray JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1get_1session_1count(JNIEnv *env, jobject instance) {
    if (pthread_mutex_lock(&lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    jintArray jarray = (*env)->NewIntArray(env, 3);
    jint *jcount = (*env)->GetIntArrayElements(env, jarray, NULL);
    jcount[0] = 0;
    jcount[1] = 0;
    jcount[2] = 0;

    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (i->socket >= 0)
            jcount[0]++;
        i = i->next;
    }

    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->socket >= 0)
            jcount[1]++;
        u = u->next;
    }

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->socket >= 0)
            jcount[2]++;
        t = t->next;
    }

    if (pthread_mutex_unlock(&lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");


    (*env)->ReleaseIntArrayElements(env, jarray, jcount, NULL);
    return jarray;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1pcap(JNIEnv *env, jclass type, jstring name_) {
    if (pthread_mutex_lock(&lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    if (name_ == NULL) {
        if (pcap_file != NULL) {
            int flags = fcntl(fileno(pcap_file), F_GETFL, 0);
            if (flags < 0 || fcntl(fileno(pcap_file), F_SETFL, flags & ~O_NONBLOCK) < 0)
                log_android(ANDROID_LOG_ERROR, "PCAP fcntl ~O_NONBLOCK error %d: %s",
                            errno, strerror(errno));

            if (fsync(fileno(pcap_file)))
                log_android(ANDROID_LOG_ERROR, "PCAP fsync error %d: %s", errno, strerror(errno));

            if (fclose(pcap_file))
                log_android(ANDROID_LOG_ERROR, "PCAP fclose error %d: %s", errno, strerror(errno));

            pcap_file = NULL;
        }
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

            if (ftell(pcap_file) == 0) {
                log_android(ANDROID_LOG_INFO, "Initializing PCAP");
                write_pcap_hdr();
            }
        }

        (*env)->ReleaseStringUTFChars(env, name_, name);
    }

    if (pthread_mutex_unlock(&lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");
}


JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1done(JNIEnv *env, jobject instance) {
    log_android(ANDROID_LOG_INFO, "Done");

    clear_sessions();

    if (pthread_mutex_destroy(&lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_destroy failed");
}

// JNI Util

JNIEXPORT jstring JNICALL
Java_eu_faircode_netguard_Util_jni_1getprop(JNIEnv *env, jclass type, jstring name_) {
    const char *name = (*env)->GetStringUTFChars(env, name_, 0);

    char value[250] = "";
    __system_property_get(env, name, value);

    (*env)->ReleaseStringUTFChars(env, name_, name);

    return (*env)->NewStringUTF(env, value);
}

// Private functions

void clear_sessions() {
    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (i->socket >= 0 && close(i->socket))
            log_android(ANDROID_LOG_ERROR, "ICMP close %d error %d: %s",
                        i->socket, errno, strerror(errno));
        struct icmp_session *p = i;
        i = i->next;
        free(p);
    }
    icmp_session = NULL;

    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->socket >= 0 && close(u->socket))
            log_android(ANDROID_LOG_ERROR, "UDP close %d error %d: %s",
                        u->socket, errno, strerror(errno));
        struct udp_session *p = u;
        u = u->next;
        free(p);
    }
    udp_session = NULL;

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->socket >= 0 && close(t->socket))
            log_android(ANDROID_LOG_ERROR, "TCP close %d error %d: %s",
                        u->socket, errno, strerror(errno));
        struct tcp_session *p = t;
        t = t->next;
        clear_tcp_data(p);
        free(p);
    }
    tcp_session = NULL;
}

void clear_tcp_data(struct tcp_session *cur) {
    struct segment *s = cur->forward;
    while (s != NULL) {
        struct segment *p = s;
        s = s->next;
        free(p->data);
        free(p);
    }
}

void handle_signal(int sig, siginfo_t *info, void *context) {
    log_android(ANDROID_LOG_DEBUG, "Signal %d", sig);
    signaled = 1;
}

void *handle_events(void *a) {
    int sdk;
    fd_set rfds;
    fd_set wfds;
    fd_set efds;
    struct timespec ts;
    sigset_t blockset;
    sigset_t emptyset;
    struct sigaction sa;

    struct arguments *args = (struct arguments *) a;
    log_android(ANDROID_LOG_WARN, "Start events tun=%d thread %x", args->tun, thread_id);

    // Attach to Java
    JNIEnv *env;
    jint rs = (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    if (rs != JNI_OK) {
        log_android(ANDROID_LOG_ERROR, "AttachCurrentThread failed");
        return NULL;
    }
    args->env = env;

    // Get SDK version
    sdk = sdk_int(env);

    // Block SIGUSR1
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blockset, NULL);

    /// Handle SIGUSR1
    sa.sa_sigaction = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    // Terminate existing sessions not allowed anymore
    check_allowed(args);

    stopping = 0;
    signaled = 0;

    // Loop
    while (!stopping) {
        log_android(ANDROID_LOG_DEBUG, "Loop thread %x", thread_id);

        // Count sessions
        int isessions = 0;
        struct icmp_session *i = icmp_session;
        while (i != NULL) {
            if (!i->stop)
                isessions++;
            i = i->next;
        }
        int usessions = 0;
        struct udp_session *u = udp_session;
        while (u != NULL) {
            if (u->state == UDP_ACTIVE)
                usessions++;
            u = u->next;
        }
        int tsessions = 0;
        struct tcp_session *t = tcp_session;
        while (t != NULL) {
            if (t->state != TCP_CLOSING && t->state != TCP_CLOSE)
                tsessions++;
            t = t->next;
        }

        // Check sessions
        check_sessions(args, isessions, usessions, tsessions);
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1093893
        int idle = (tsessions + usessions + tsessions == 0 && sdk >= 16);
        log_android(ANDROID_LOG_DEBUG, "sessions ICMP %d UDP %d TCP %d idle %d sdk %d",
                    isessions, usessions, tsessions, idle, sdk);

        // Next event time
        ts.tv_sec = (sdk < 16 ? 5 : get_select_timeout(isessions, usessions, tsessions));
        ts.tv_nsec = 0;
        sigemptyset(&emptyset);

        // Check if tun is writable
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(args->tun, &wfds);
        if (pselect(args->tun + 1, &rfds, &wfds, &efds, &ts, &emptyset) == 0) {
            log_android(ANDROID_LOG_WARN, "tun not writable");
            continue;
        }

        // Select
        int max = get_selects(args, &rfds, &wfds, &efds);
        int ready = pselect(max + 1, &rfds, &wfds, &efds, idle ? NULL : &ts, &emptyset);

        if (ready < 0) {
            if (errno == EINTR) {
                if (stopping && signaled) { ;
                    log_android(ANDROID_LOG_WARN,
                                "pselect signaled tun %d thread %x", args->tun, thread_id);
                    report_exit(args, NULL);
                    break;
                } else {
                    // TODO check if SIGUSR1 is free
                    log_android(ANDROID_LOG_DEBUG,
                                "pselect interrupted tun %d thread %x", args->tun, thread_id);
                    continue;
                }
            } else {
                log_android(ANDROID_LOG_ERROR,
                            "pselect tun %d thread %x error %d: %s",
                            args->tun, thread_id, errno, strerror(errno));
                report_exit(args, "pselect tun %d thread %x error %d: %s",
                            args->tun, thread_id, errno, strerror(errno));
                break;
            }
        }

        if (ready == 0)
            log_android(ANDROID_LOG_DEBUG, "pselect timeout");
        else {
            log_android(ANDROID_LOG_DEBUG, "pselect ready %d", ready);

            if (pthread_mutex_lock(&lock))
                log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

#ifdef PROFILE_EVENTS
            struct timeval start, end;
            float mselapsed;
            gettimeofday(&start, NULL);
#endif

            // Check upstream
            int error = 0;
            if (check_tun(args, &rfds, &wfds, &efds) < 0)
                error = 1;
            else {
#ifdef PROFILE_EVENTS
                gettimeofday(&end, NULL);
                mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                            (end.tv_usec - start.tv_usec) / 1000.0;
                if (mselapsed > PROFILE_EVENTS)
                    log_android(ANDROID_LOG_WARN, "tun %f", mselapsed);

                gettimeofday(&start, NULL);
#endif

                // Check ICMP downstream
                check_icmp_sockets(args, &rfds, &wfds, &efds);

                // Check UDP downstream
                check_udp_sockets(args, &rfds, &wfds, &efds);

                // Check TCP downstream
                check_tcp_sockets(args, &rfds, &wfds, &efds);
            }

            if (pthread_mutex_unlock(&lock))
                log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");

            if (error)
                break;

#ifdef PROFILE_EVENTS
            gettimeofday(&end, NULL);
            mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_usec - start.tv_usec) / 1000.0;
            if (mselapsed > PROFILE_EVENTS)
                log_android(ANDROID_LOG_WARN, "sockets %f", mselapsed);
#endif
        }
    }

    (*env)->DeleteGlobalRef(env, args->instance);

    // Detach from Java
    rs = (*jvm)->DetachCurrentThread(jvm);
    if (rs != JNI_OK)
        log_android(ANDROID_LOG_ERROR, "DetachCurrentThread failed");

    // Cleanup
    free(args);

    log_android(ANDROID_LOG_WARN, "Stopped events tun=%d thread %x", args->tun, thread_id);
    thread_id = 0;
    return NULL;
}

void report_exit(const struct arguments *args, const char *fmt, ...) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    jmethodID mid = jniGetMethodID(args->env, cls, "nativeExit", "(Ljava/lang/String;)V");

    jstring jreason = NULL;
    if (fmt != NULL) {
        char line[1024];
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        jreason = (*args->env)->NewStringUTF(args->env, line);
        va_end(argptr);
    }

    (*args->env)->CallVoidMethod(args->env, args->instance, mid, jreason);
    jniCheckException(args->env);

    if (jreason != NULL)
        (*args->env)->DeleteLocalRef(args->env, jreason);
    (*args->env)->DeleteLocalRef(args->env, cls);
}

void check_allowed(const struct arguments *args) {
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (!i->stop) {
            if (i->version == 4) {
                inet_ntop(AF_INET, &i->saddr.ip4, source, sizeof(source));
                inet_ntop(AF_INET, &i->daddr.ip4, dest, sizeof(dest));
            }
            else {
                inet_ntop(AF_INET6, &i->saddr.ip6, source, sizeof(source));
                inet_ntop(AF_INET6, &i->daddr.ip6, dest, sizeof(dest));
            }

            jobject objPacket = create_packet(
                    args, i->version, IPPROTO_ICMP, "",
                    source, 0, dest, 0, "", i->uid, 0);
            if (is_address_allowed(args, objPacket) == NULL) {
                i->stop = 1;
                log_android(ANDROID_LOG_WARN, "ICMP terminate %d uid %d", i->socket, i->uid);
            }
        }
        i = i->next;
    }

    struct udp_session *l = NULL;
    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->state == UDP_ACTIVE) {
            if (u->version == 4) {
                inet_ntop(AF_INET, &u->saddr.ip4, source, sizeof(source));
                inet_ntop(AF_INET, &u->daddr.ip4, dest, sizeof(dest));
            }
            else {
                inet_ntop(AF_INET6, &u->saddr.ip6, source, sizeof(source));
                inet_ntop(AF_INET6, &u->daddr.ip6, dest, sizeof(dest));
            }

            jobject objPacket = create_packet(
                    args, u->version, IPPROTO_UDP, "",
                    source, ntohs(u->source), dest, ntohs(u->dest), "", u->uid, 0);
            if (is_address_allowed(args, objPacket) == NULL) {
                u->state = UDP_FINISHING;
                log_android(ANDROID_LOG_WARN, "UDP terminate session socket %d uid %d",
                            u->socket, u->uid);
            }
        }
        else if (u->state == UDP_BLOCKED) {
            log_android(ANDROID_LOG_WARN, "UDP remove blocked session uid %d", u->uid);

            if (l == NULL)
                udp_session = u->next;
            else
                l->next = u->next;

            struct udp_session *c = u;
            u = u->next;
            free(c);
            continue;
        }
        l = u;
        u = u->next;
    }

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->state != TCP_CLOSING && t->state != TCP_CLOSE) {
            if (t->version == 4) {
                inet_ntop(AF_INET, &t->saddr.ip4, source, sizeof(source));
                inet_ntop(AF_INET, &t->daddr.ip4, dest, sizeof(dest));
            }
            else {
                inet_ntop(AF_INET6, &t->saddr.ip6, source, sizeof(source));
                inet_ntop(AF_INET6, &t->daddr.ip6, dest, sizeof(dest));
            }

            jobject objPacket = create_packet(
                    args, t->version, IPPROTO_TCP, "",
                    source, ntohs(t->source), dest, ntohs(t->dest), "", t->uid, 0);
            if (is_address_allowed(args, objPacket) == NULL) {
                write_rst(args, t);
                log_android(ANDROID_LOG_WARN, "TCP terminate socket %d uid %d",
                            t->socket, t->uid);
            }
        }
        t = t->next;
    }
}

void check_sessions(const struct arguments *args, int isessions, int usessions, int tsessions) {
    time_t now = time(NULL);

    // Check ICMP sessions
    struct icmp_session *il = NULL;
    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        int timeout = ICMP_TIMEOUT;
        if (i->stop || i->time + timeout < now) {
            char source[INET6_ADDRSTRLEN + 1];
            char dest[INET6_ADDRSTRLEN + 1];
            if (i->version == 4) {
                inet_ntop(AF_INET, &i->saddr.ip4, source, sizeof(source));
                inet_ntop(AF_INET, &i->daddr.ip4, dest, sizeof(dest));
            }
            else {
                inet_ntop(AF_INET6, &i->saddr.ip6, source, sizeof(source));
                inet_ntop(AF_INET6, &i->daddr.ip6, dest, sizeof(dest));
            }
            log_android(ANDROID_LOG_WARN, "ICMP idle %d/%d sec stop %d from %s to %s",
                        now - i->time, timeout, i->stop, dest, source);

            if (close(i->socket))
                log_android(ANDROID_LOG_ERROR, "ICMP close %d error %d: %s",
                            i->socket, errno, strerror(errno));
            i->socket = -1;

            if (il == NULL)
                icmp_session = i->next;
            else
                il->next = i->next;

            struct icmp_session *c = i;
            i = i->next;
            free(c);
        }
        else {
            il = i;
            i = i->next;
        }
    }

    // Check UDP sessions
    struct udp_session *ul = NULL;
    struct udp_session *u = udp_session;
    while (u != NULL) {
        char source[INET6_ADDRSTRLEN + 1];
        char dest[INET6_ADDRSTRLEN + 1];
        if (u->version == 4) {
            inet_ntop(AF_INET, &u->saddr.ip4, source, sizeof(source));
            inet_ntop(AF_INET, &u->daddr.ip4, dest, sizeof(dest));
        }
        else {
            inet_ntop(AF_INET6, &u->saddr.ip6, source, sizeof(source));
            inet_ntop(AF_INET6, &u->daddr.ip6, dest, sizeof(dest));
        }

        // Check session timeout
        int timeout = get_udp_timeout(u, usessions);
        if (u->state == UDP_ACTIVE && u->time + timeout < now) {
            log_android(ANDROID_LOG_WARN, "UDP idle %d/%d sec state %d from %s/%u to %s/%u",
                        now - u->time, timeout, u->state,
                        source, ntohs(u->source), dest, ntohs(u->dest));
            u->state = UDP_FINISHING;
        }

        // Check finished sessions
        if (u->state == UDP_FINISHING) {
            log_android(ANDROID_LOG_INFO, "UDP close from %s/%u to %s/%u socket %d",
                        source, ntohs(u->source), dest, ntohs(u->dest), u->socket);

            if (close(u->socket))
                log_android(ANDROID_LOG_ERROR, "UDP close %d error %d: %s",
                            u->socket, errno, strerror(errno));
            u->socket = -1;

            u->time = time(NULL);
            u->state = UDP_CLOSED;
        }

        // Cleanup lingering sessions
        if ((u->state == UDP_CLOSED || u->state == UDP_BLOCKED) &&
            u->time + UDP_KEEP_TIMEOUT < now) {
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
        char source[INET6_ADDRSTRLEN + 1];
        char dest[INET6_ADDRSTRLEN + 1];
        if (t->version == 4) {
            inet_ntop(AF_INET, &t->saddr.ip4, source, sizeof(source));
            inet_ntop(AF_INET, &t->daddr.ip4, dest, sizeof(dest));
        } else {
            inet_ntop(AF_INET6, &t->saddr.ip6, source, sizeof(source));
            inet_ntop(AF_INET6, &t->daddr.ip6, dest, sizeof(dest));
        }

        char session[250];
        sprintf(session, "TCP socket from %s/%u to %s/%u %s socket %d",
                source, ntohs(t->source), dest, ntohs(t->dest), strstate(t->state), t->socket);

        // Check session timeout
        int timeout = get_tcp_timeout(t, tsessions);
        if (t->state != TCP_CLOSING && t->state != TCP_CLOSE && t->time + timeout < now) {
            // TODO send keep alives?
            log_android(ANDROID_LOG_WARN, "%s idle %d/%d sec ",
                        session, now - t->time, timeout);
            if (t->state == TCP_CLOSE_WAIT && t->forward == NULL) {
                t->remote_seq++; // remote FIN
                if (write_fin_ack(args, t) >= 0) {
                    log_android(ANDROID_LOG_WARN, "%s finished idle", session);
                    t->local_seq++; // local FIN
                    t->state = TCP_LAST_ACK;
                }
            }
            else {
                log_android(ANDROID_LOG_WARN, "%s reset idle", session);
                write_rst(args, t);
            }
        }

        // Check closing sessions
        if (t->state == TCP_CLOSING) {
            if (t->socket >= 0) {
                if (close(t->socket))
                    log_android(ANDROID_LOG_ERROR, "%s close error %d: %s",
                                session, errno, strerror(errno));
                else
                    log_android(ANDROID_LOG_WARN, "%s close", session);
                t->socket = -1;
            }

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
            clear_tcp_data(c);
            free(c);
        }
        else {
            tl = t;
            t = t->next;
        }
    }
}

int get_select_timeout(int isessions, int usessions, int tsessions) {
    time_t now = time(NULL);
    int timeout = SELECT_TIMEOUT;

    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (!i->stop) {
            int stimeout = i->time + ICMP_TIMEOUT - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        i = i->next;
    }

    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->state == UDP_ACTIVE) {
            int stimeout = u->time + get_udp_timeout(u, usessions) - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        u = u->next;
    }

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->state != TCP_CLOSING && t->state != TCP_CLOSE) {
            int stimeout = t->time + get_tcp_timeout(t, tsessions) - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        t = t->next;
    }

    return timeout;
}

int get_udp_timeout(const struct udp_session *u, int sessions) {
    int timeout = (ntohs(u->dest) == 53 ? UDP_TIMEOUT_53 : UDP_TIMEOUT_ANY);

    int scale = sessions / UDP_TIMEOUT_SCALE;
    if (scale < 1)
        scale = 1;
    timeout = timeout / scale;

    return timeout;
}

int get_tcp_timeout(const struct tcp_session *t, int sessions) {
    int timeout;
    if (t->state == TCP_LISTEN || t->state == TCP_SYN_RECV)
        timeout = TCP_INIT_TIMEOUT;
    else if (t->state == TCP_ESTABLISHED && t->socket >= 0)
        timeout = TCP_IDLE_TIMEOUT;
    else
        timeout = TCP_CLOSE_TIMEOUT;

    int scale = sessions / TCP_TIMEOUT_SCALE;
    if (scale < 1)
        scale = 1;
    timeout = timeout / scale;

    return timeout;
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

    // Select ICMP sockets
    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (!i->stop) {
            FD_SET(i->socket, efds);
            FD_SET(i->socket, rfds);
            if (i->socket > max)
                max = i->socket;
        }
        i = i->next;
    }

    // Select UDP sockets
    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->state == UDP_ACTIVE) {
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
        if (t->socket >= 0) {
            if (t->state == TCP_LISTEN) {
                // Check for errors
                FD_SET(t->socket, efds);

                // Check for connected = writable
                FD_SET(t->socket, wfds);

                if (t->socket > max)
                    max = t->socket;
            }
            else if (t->state == TCP_ESTABLISHED || t->state == TCP_CLOSE_WAIT) {
                // Check errors
                FD_SET(t->socket, efds);

                // Check for incoming data
                if (t->send_window > 0)
                    FD_SET(t->socket, rfds);

                // Check for outgoing data
                if (t->forward != NULL)
                    FD_SET(t->socket, wfds);

                if (t->socket > max)
                    max = t->socket;
            }
        }

        t = t->next;
    }

    return max;
}

int check_tun(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    // Check tun error
    if (FD_ISSET(args->tun, efds)) {
        log_android(ANDROID_LOG_ERROR, "tun %d exception", args->tun);
        if (fcntl(args->tun, F_GETFL) < 0) {
            log_android(ANDROID_LOG_ERROR, "fcntl tun %d F_GETFL error %d: %s",
                        args->tun, errno, strerror(errno));
            report_exit(args, "fcntl tun %d F_GETFL error %d: %s",
                        args->tun, errno, strerror(errno));
        } else
            report_exit(args, "tun %d exception", args->tun);
        return -1;
    }

    // Check tun read
    if (FD_ISSET(args->tun, rfds)) {
        uint8_t *buffer = malloc(TUN_MAXMSG);
        ssize_t length = read(args->tun, buffer, TUN_MAXMSG);
        if (length < 0) {
            free(buffer);

            log_android(ANDROID_LOG_ERROR, "tun read error %d: %s", errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN)
                // Retry later
                return 0;
            else {
                report_exit(args, "tun read error %d: %s", errno, strerror(errno));
                return -1;
            }
        }
        else if (length > 0) {
            // Write pcap record
            if (pcap_file != NULL)
                write_pcap_rec(buffer, (size_t) length);

            if (length > max_tun_msg) {
                max_tun_msg = length;
                log_android(ANDROID_LOG_WARN, "Maximum tun msg length %d", max_tun_msg);
            }

            // Handle IP from tun
            handle_ip(args, buffer, (size_t) length);

            free(buffer);
        }
        else {
            // tun eof
            free(buffer);

            log_android(ANDROID_LOG_ERROR, "tun %d empty read", args->tun);
            report_exit(args, "tun %d empty read", args->tun);
            return -1;
        }
    }

    return 0;
}

void check_icmp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct icmp_session *cur = icmp_session;
    while (cur != NULL) {
        if (cur->socket >= 0) {
            // Check socket error
            if (FD_ISSET(cur->socket, efds)) {
                cur->time = time(NULL);

                int serr = 0;
                socklen_t optlen = sizeof(int);
                int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
                if (err < 0)
                    log_android(ANDROID_LOG_ERROR, "ICMP getsockopt error %d: %s",
                                errno, strerror(errno));
                else if (serr)
                    log_android(ANDROID_LOG_ERROR, "ICMP SO_ERROR %d: %s",
                                serr, strerror(serr));

                cur->stop = 1;
            }
            else {
                // Check socket read
                if (FD_ISSET(cur->socket, rfds)) {
                    cur->time = time(NULL);

                    uint16_t blen = (uint16_t) (cur->version == 4 ? ICMP4_MAXMSG : ICMP6_MAXMSG);
                    uint8_t *buffer = malloc(blen);
                    ssize_t bytes = recv(cur->socket, buffer, blen, 0);
                    if (bytes < 0) {
                        // Socket error
                        log_android(ANDROID_LOG_WARN, "ICMP recv error %d: %s",
                                    errno, strerror(errno));

                        if (errno != EINTR && errno != EAGAIN)
                            cur->stop = 1;
                    }
                    else if (bytes == 0) {
                        log_android(ANDROID_LOG_WARN, "ICMP recv eof");
                        cur->stop = 1;

                    } else {
                        // Socket read data
                        char dest[INET6_ADDRSTRLEN + 1];
                        if (cur->version == 4)
                            inet_ntop(AF_INET, &cur->daddr.ip4, dest, sizeof(dest));
                        else
                            inet_ntop(AF_INET6, &cur->daddr.ip6, dest, sizeof(dest));

                        // cur->id should be equal to icmp->icmp_id
                        // but for some unexplained reason this is not the case
                        // some bits seems to be set extra
                        struct icmp *icmp = (struct icmp *) buffer;
                        log_android(
                                cur->id == icmp->icmp_id ? ANDROID_LOG_INFO : ANDROID_LOG_WARN,
                                "ICMP recv bytes %d from %s for tun type %d code %d id %x/%x seq %d",
                                bytes, dest,
                                icmp->icmp_type, icmp->icmp_code,
                                cur->id, icmp->icmp_id, icmp->icmp_seq);

                        // restore original ID
                        icmp->icmp_id = cur->id;
                        uint16_t csum = 0;
                        if (cur->version == 6) {
                            // Untested
                            struct ip6_hdr_pseudo pseudo;
                            memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
                            memcpy(&pseudo.ip6ph_src, &cur->daddr.ip6, 16);
                            memcpy(&pseudo.ip6ph_dst, &cur->saddr.ip6, 16);
                            pseudo.ip6ph_len = bytes - sizeof(struct ip6_hdr);
                            pseudo.ip6ph_nxt = IPPROTO_ICMPV6;
                            csum = calc_checksum(
                                    0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
                        }
                        icmp->icmp_cksum = 0;
                        icmp->icmp_cksum = ~calc_checksum(csum, buffer, (size_t) bytes);

                        // Forward to tun
                        if (write_icmp(args, cur, buffer, (size_t) bytes) < 0)
                            cur->stop = 1;
                    }
                    free(buffer);
                }
            }
        }
        cur = cur->next;
    }
}

void check_udp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct udp_session *cur = udp_session;
    while (cur != NULL) {
        if (cur->socket >= 0) {
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

                cur->state = UDP_FINISHING;
            }
            else {
                // Check socket read
                if (FD_ISSET(cur->socket, rfds)) {
                    cur->time = time(NULL);

                    uint16_t blen = (uint16_t) (cur->version == 4 ? UDP4_MAXMSG : UDP6_MAXMSG);
                    uint8_t *buffer = malloc(blen);
                    ssize_t bytes = recv(cur->socket, buffer, blen, 0);
                    if (bytes < 0) {
                        // Socket error
                        log_android(ANDROID_LOG_WARN, "UDP recv error %d: %s",
                                    errno, strerror(errno));

                        if (errno != EINTR && errno != EAGAIN)
                            cur->state = UDP_FINISHING;
                    }
                    else if (bytes == 0) {
                        log_android(ANDROID_LOG_WARN, "UDP recv eof");
                        cur->state = UDP_FINISHING;

                    } else {
                        // Socket read data
                        char dest[INET6_ADDRSTRLEN + 1];
                        if (cur->version == 4)
                            inet_ntop(AF_INET, &cur->daddr.ip4, dest, sizeof(dest));
                        else
                            inet_ntop(AF_INET6, &cur->daddr.ip6, dest, sizeof(dest));
                        log_android(ANDROID_LOG_INFO, "UDP recv bytes %d from %s/%u for tun",
                                    bytes, dest, ntohs(cur->dest));

                        // Process DNS response
                        if (ntohs(cur->dest) == 53)
                            parse_dns_response(args, buffer, (size_t) bytes);

                        // Forward to tun
                        if (write_udp(args, cur, buffer, (size_t) bytes) < 0)
                            cur->state = UDP_FINISHING;
                        else {
                            // Prevent too many open files
                            if (ntohs(cur->dest) == 53)
                                cur->state = UDP_FINISHING;
                        }
                    }
                    free(buffer);
                }
            }
        }
        cur = cur->next;
    }
}

int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname) {
    *qname = 0;

    uint16_t c = 0;
    uint8_t noff = 0;
    uint16_t ptr = off;
    uint8_t len = *(data + ptr);
    uint8_t parts = 0;
    while (len && parts < 10) {
        parts++;
        if (len & 0xC0) {
            ptr = (uint16_t) ((len & 0x3F) * 256 + *(data + ptr + 1));
            len = *(data + ptr);
            log_android(ANDROID_LOG_DEBUG, "DNS qname compression ptr %d len %d", ptr, len);
            if (!c) {
                c = 1;
                off += 2;
            }
        }
        else if (ptr + 1 + len <= datalen) {
            memcpy(qname + noff, data + ptr + 1, len);
            *(qname + noff + len) = '.';
            noff += (len + 1);

            ptr += (len + 1);
            len = *(data + ptr);
        }
        else
            break;
    }
    ptr++;

    if (len > 0 || noff == 0) {
        log_android(ANDROID_LOG_ERROR, "DNS qname invalid len %d noff %d part %d", len, noff,
                    parts);
        return -1;
    }

    *(qname + noff - 1) = 0;

    return (c ? off : ptr);
}

void parse_dns_response(const struct arguments *args, const uint8_t *data, const size_t datalen) {
    if (datalen < sizeof(struct dns_header) + 1) {
        log_android(ANDROID_LOG_WARN, "DNS response length %d", datalen);
        return;
    }

    // Check if standard DNS query
    // TODO multiple qnames
    const struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    int acount = ntohs(dns->ans_count);
    if (dns->qr == 1 && dns->opcode == 0 && qcount > 0 && acount > 0) {
        log_android(ANDROID_LOG_DEBUG, "DNS response qcount %d acount %d", qcount, acount);
        if (qcount > 1)
            log_android(ANDROID_LOG_WARN, "DNS response qcount %d acount %d", qcount, acount);

        // http://tools.ietf.org/html/rfc1035
        char qname[DNS_QNAME_MAX + 1];

        char name[DNS_QNAME_MAX + 1];
        int32_t off = sizeof(struct dns_header);
        for (int q = 0; q < qcount; q++) {
            off = get_qname(data, datalen, (uint16_t) off, name);
            if (off > 0 && off + 4 <= datalen) {
                uint16_t qtype = ntohs(*((uint16_t *) (data + off)));
                uint16_t qclass = ntohs(*((uint16_t *) (data + off + 2)));
                log_android(ANDROID_LOG_DEBUG,
                            "DNS question %d qtype %d qclass %d qname %s",
                            q, qtype, qclass, name);
                off += 4;

                // TODO multiple qnames?
                if (q == 0)
                    strcpy(qname, name);
            }
            else {
                log_android(ANDROID_LOG_WARN,
                            "DNS response Q invalid off %d datalen %d",
                            off, datalen);
                return;
            }
        }

        for (int a = 0; a < acount; a++) {
            off = get_qname(data, datalen, (uint16_t) off, name);
            if (off > 0 && off + 10 <= datalen) {
                uint16_t qtype = ntohs(*((uint16_t *) (data + off)));
                uint16_t qclass = ntohs(*((uint16_t *) (data + off + 2)));
                uint32_t ttl = ntohl(*((uint32_t *) (data + off + 4)));
                uint16_t rdlength = ntohs(*((uint16_t *) (data + off + 8)));
                off += 10;

                if (off + rdlength <= datalen) {
                    if (qclass == DNS_QCLASS_IN &&
                        (qtype == DNS_QTYPE_A || qtype == DNS_QTYPE_AAAA)) {

                        char rd[INET6_ADDRSTRLEN + 1];
                        if (qtype == DNS_QTYPE_A)
                            inet_ntop(AF_INET, data + off, rd, sizeof(rd));
                        else if (qclass == DNS_QCLASS_IN && qtype == DNS_QTYPE_AAAA)
                            inet_ntop(AF_INET6, data + off, rd, sizeof(rd));

                        dns_resolved(args, qname, name, rd, ttl);
                        log_android(ANDROID_LOG_DEBUG,
                                    "DNS answer %d qname %s qtype %d ttl %d data %s",
                                    a, name, qtype, ttl, rd);

                    } else
                        log_android(ANDROID_LOG_DEBUG,
                                    "DNS answer %d qname %s qclass %d qtype %d ttl %d length %d",
                                    a, name, qclass, qtype, ttl, rdlength);

                    off += rdlength;
                }
                else {
                    log_android(ANDROID_LOG_WARN,
                                "DNS response A invalid off %d rdlength %d datalen %d",
                                off, rdlength, datalen);
                    return;
                }
            }
            else {
                log_android(ANDROID_LOG_WARN,
                            "DNS response A invalid off %d datalen %d",
                            off, datalen);
                return;
            }
        }
    }
    else if (acount > 0)
        log_android(ANDROID_LOG_WARN,
                    "DNS response qr %d opcode %d qcount %d acount %d",
                    dns->qr, dns->opcode, qcount, acount);
}

void check_tcp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct tcp_session *cur = tcp_session;
    while (cur != NULL) {
        if (cur->socket >= 1) {
            int oldstate = cur->state;
            uint32_t oldlocal = cur->local_seq;
            uint32_t oldremote = cur->remote_seq;

            // TODO if logging
            char source[INET6_ADDRSTRLEN + 1];
            char dest[INET6_ADDRSTRLEN + 1];
            if (cur->version == 4) {
                inet_ntop(AF_INET, &cur->saddr.ip4, source, sizeof(source));
                inet_ntop(AF_INET, &cur->daddr.ip4, dest, sizeof(dest));
            } else {
                inet_ntop(AF_INET6, &cur->saddr.ip6, source, sizeof(source));
                inet_ntop(AF_INET6, &cur->daddr.ip6, dest, sizeof(dest));
            }
            char session[250];
            sprintf(session, "TCP socket from %s/%u to %s/%u %s loc %u rem %u",
                    source, ntohs(cur->source), dest, ntohs(cur->dest),
                    strstate(cur->state),
                    cur->local_seq - cur->local_start,
                    cur->remote_seq - cur->remote_start);

            // Check socket error
            if (FD_ISSET(cur->socket, efds)) {
                cur->time = time(NULL);

                int serr = 0;
                socklen_t optlen = sizeof(int);
                int err = getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen);
                if (err < 0)
                    log_android(ANDROID_LOG_ERROR, "%s getsockopt error %d: %s",
                                session, errno, strerror(errno));
                else if (serr)
                    log_android(ANDROID_LOG_ERROR, "%s SO_ERROR %d: %s",
                                session, serr, strerror(serr));

                write_rst(args, cur);
            }
            else {
                // Assume socket okay
                if (cur->state == TCP_LISTEN) {
                    // Check socket connect
                    if (FD_ISSET(cur->socket, wfds)) {
                        cur->time = time(NULL);

                        log_android(ANDROID_LOG_INFO, "%s connected", session);

                        if (write_syn_ack(args, cur) >= 0) {
                            cur->local_seq++; // local SYN
                            cur->remote_seq++; // remote SYN
                            cur->state = TCP_SYN_RECV;
                        }
                    }
                } else {
                    // Calculate recv window
                    int unsent = 0;
                    int window = TCP_RECV_WINDOW;
                    if (cur->socket >= 0) {
                        if (ioctl(cur->socket, SIOCOUTQ, &unsent))
                            log_android(ANDROID_LOG_WARN, "ioctl SIOCOUTQ %d: %s",
                                        errno, strerror(errno));
                        else {
                            struct segment *q = cur->forward;
                            while (q != NULL) {
                                unsent += q->len;
                                q = q->next;
                            }
                            window = (unsent < TCP_RECV_WINDOW ? TCP_RECV_WINDOW - unsent : 0);
                        }
                    }

                    int prev = cur->recv_window;
                    cur->recv_window = window;
                    if ((prev == 0 && window > 0) || (prev > 0 && window == 0))
                        log_android(ANDROID_LOG_WARN, "%s recv window %d > %d",
                                    session, prev, window);

                    // Always forward data
                    int fwd = 0;
                    if (FD_ISSET(cur->socket, wfds)) {
                        // Forward data
                        while (cur->forward != NULL && cur->forward->seq == cur->remote_seq) {
                            log_android(ANDROID_LOG_DEBUG, "%s fwd %u...%u",
                                        session,
                                        cur->forward->seq - cur->remote_start,
                                        cur->forward->seq + cur->forward->len - cur->remote_start);

                            if (send(cur->socket, cur->forward->data, cur->forward->len,
                                     MSG_NOSIGNAL | (cur->forward->psh ? 0 : MSG_MORE)) < 0) {
                                log_android(ANDROID_LOG_ERROR, "%s send error %d: %s",
                                            session, errno, strerror(errno));
                                if (errno == EINTR || errno == EAGAIN) {
                                    // Retry later
                                    break;
                                } else {
                                    write_rst(args, cur);
                                    break;
                                }
                            } else {
                                fwd = 1;
                                cur->time = time(NULL);
                                cur->remote_seq = cur->forward->seq + cur->forward->len;

                                struct segment *p = cur->forward;
                                cur->forward = cur->forward->next;
                                free(p->data);
                                free(p);
                            }
                        }

                        // Log data buffered
                        struct segment *s = cur->forward;
                        while (s != NULL) {
                            log_android(ANDROID_LOG_WARN, "%s queued %u...%u",
                                        session,
                                        s->seq - cur->remote_start,
                                        s->seq + s->len - cur->remote_start);
                            s = s->next;
                        }
                    }

                    // Acknowledge forwarded data
                    // TODO send less ACKs?
                    if (fwd || (prev == 0 && window > 0))
                        write_ack(args, cur, 0);

                    if (cur->state == TCP_ESTABLISHED || cur->state == TCP_CLOSE_WAIT) {
                        // Check socket read
                        // Send window can be changed in the mean time
                        if (FD_ISSET(cur->socket, rfds) && cur->send_window > 0) {
                            cur->time = time(NULL);

                            size_t len = (cur->send_window > TCP_SEND_WINDOW
                                          ? TCP_SEND_WINDOW
                                          : cur->send_window);
                            uint8_t *buffer = malloc(len);
                            ssize_t bytes = recv(cur->socket, buffer, len, 0);
                            if (bytes < 0) {
                                // Socket error
                                log_android(ANDROID_LOG_ERROR, "%s recv error %d: %s",
                                            session, errno, strerror(errno));

                                if (errno != EINTR && errno != EAGAIN)
                                    write_rst(args, cur);
                            }
                            else if (bytes == 0) {
                                log_android(ANDROID_LOG_WARN, "%s recv eof", session);

                                if (cur->forward == NULL) {
                                    if (cur->state == TCP_CLOSE_WAIT) {
                                        cur->remote_seq++; // remote FIN
                                        if (write_fin_ack(args, cur) >= 0) {
                                            log_android(ANDROID_LOG_WARN, "%s finished eof",
                                                        session);
                                            cur->local_seq++; // local FIN
                                            cur->state = TCP_LAST_ACK;
                                        }
                                    } else
                                        log_android(ANDROID_LOG_WARN, "%s close linger", session);
                                }
                                else {
                                    // There was still data to send
                                    log_android(ANDROID_LOG_ERROR, "%s close with data queued",
                                                session);
                                    write_rst(args, cur);
                                }

                                if (close(cur->socket))
                                    log_android(ANDROID_LOG_ERROR, "%s close error %d: %s",
                                                session, errno, strerror(errno));
                                cur->socket = -1;

                            } else {
                                // Socket read data
                                log_android(ANDROID_LOG_DEBUG, "%s recv bytes %d", session, bytes);

                                // Forward to tun
                                if (write_data(args, cur, buffer, (size_t) bytes) >= 0)
                                    cur->local_seq += bytes;
                            }
                            free(buffer);
                        }
                    }
                }
            }

            if (cur->state != oldstate || cur->local_seq != oldlocal ||
                cur->remote_seq != oldremote)
                log_android(ANDROID_LOG_DEBUG, "%s new state", session);
        }
        cur = cur->next;
    }
}

// https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers
// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
int is_lower_layer(int protocol) {
    // No next header = 59
    return (protocol == 0 || // Hop-by-Hop Options
            protocol == 60 || // Destination Options (before routing header)
            protocol == 43 || // Routing
            protocol == 44 || // Fragment
            protocol == 51 || // Authentication Header (AH)
            protocol == 50 || // Encapsulating Security Payload (ESP)
            protocol == 60 || // Destination Options (before upper-layer header)
            protocol == 135); // Mobility
}

int is_upper_layer(int protocol) {
    return (protocol == IPPROTO_TCP ||
            protocol == IPPROTO_UDP ||
            protocol == IPPROTO_ICMP ||
            protocol == IPPROTO_ICMPV6);
}

void handle_ip(const struct arguments *args, const uint8_t *pkt, const size_t length) {
    uint8_t protocol;
    void *saddr;
    void *daddr;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    char flags[10];
    int flen = 0;
    uint8_t *payload;

#ifdef PROFILE_EVENTS
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Get protocol, addresses & payload
    uint8_t version = (*pkt) >> 4;
    if (version == 4) {
        if (length < sizeof(struct iphdr)) {
            log_android(ANDROID_LOG_WARN, "IP4 packet too short length %d", length);
            return;
        }

        struct iphdr *ip4hdr = (struct iphdr *) pkt;

        protocol = ip4hdr->protocol;
        saddr = &ip4hdr->saddr;
        daddr = &ip4hdr->daddr;

        if (ip4hdr->frag_off & IP_MF) {
            log_android(ANDROID_LOG_ERROR, "IP fragment");
            flags[flen++] = '+';
        }

        uint8_t ipoptlen = (uint8_t) ((ip4hdr->ihl - 5) * 4);
        payload = (uint8_t *) (pkt + sizeof(struct iphdr) + ipoptlen);

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
        if (length < sizeof(struct ip6_hdr)) {
            log_android(ANDROID_LOG_WARN, "IP6 packet too short length %d", length);
            return;
        }

        struct ip6_hdr *ip6hdr = (struct ip6_hdr *) pkt;

        // Skip extension headers
        uint16_t off = 0;
        protocol = ip6hdr->ip6_nxt;
        if (!is_upper_layer(protocol)) {
            log_android(ANDROID_LOG_WARN, "IP6 extension %d", protocol);
            off = sizeof(struct ip6_hdr);
            struct ip6_ext *ext = (struct ip6_ext *) (pkt + off);
            while (is_lower_layer(ext->ip6e_nxt) && !is_upper_layer(protocol)) {
                protocol = ext->ip6e_nxt;
                log_android(ANDROID_LOG_WARN, "IP6 extension %d", protocol);

                off += (8 + ext->ip6e_len);
                ext = (struct ip6_ext *) (pkt + off);
            }
            if (!is_upper_layer(protocol)) {
                off = 0;
                protocol = ip6hdr->ip6_nxt;
                log_android(ANDROID_LOG_WARN, "IP6 final extension %d", protocol);
            }
        }

        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;

        payload = (uint8_t *) (pkt + sizeof(struct ip6_hdr) + off);

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
    uint16_t sport = 0;
    uint16_t dport = 0;
    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
        if (length - (payload - pkt) < sizeof(struct icmp)) {
            log_android(ANDROID_LOG_WARN, "ICMP packet too short");
            return;
        }

        struct icmp *icmp = (struct icmp *) payload;

        // http://lwn.net/Articles/443051/
        sport = ntohs(icmp->icmp_id);
        dport = ntohs(icmp->icmp_id);

    } else if (protocol == IPPROTO_UDP) {
        if (length - (payload - pkt) < sizeof(struct udphdr)) {
            log_android(ANDROID_LOG_WARN, "UDP packet too short");
            return;
        }

        struct udphdr *udp = (struct udphdr *) payload;

        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);

        // TODO checksum (IPv6)
    }
    else if (protocol == IPPROTO_TCP) {
        if (length - (payload - pkt) < sizeof(struct tcphdr)) {
            log_android(ANDROID_LOG_WARN, "TCP packet too short");
            return;
        }

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
    }
    flags[flen] = 0;

    // Get uid
    jint uid = -1;
    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6 ||
        (protocol == IPPROTO_UDP && !has_udp_session(args, pkt, payload)) ||
        (protocol == IPPROTO_TCP && syn)) {
        log_android(ANDROID_LOG_INFO, "get uid %s/%u version %d protocol %d syn %d",
                    dest, dport, version, protocol, syn);
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
                uid = get_uid(protocol, 6, saddr128, sport, dump);
            }

            if (uid < 0)
                uid = get_uid(protocol, version, saddr, sport, dump);

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
                "Packet v%d %s/%u > %s/%u proto %d flags %s uid %d",
                version, source, sport, dest, dport, protocol, flags, uid);

#ifdef PROFILE_EVENTS
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_EVENTS)
        log_android(ANDROID_LOG_WARN, "handle ip %f", mselapsed);
#endif

    // Check if allowed
    int allowed = 0;
    struct allowed *redirect = NULL;
    if (protocol == IPPROTO_UDP && has_udp_session(args, pkt, payload))
        allowed = 1; // could be a lingering/blocked session
    else if (protocol == IPPROTO_TCP && !syn)
        allowed = 1; // assume existing session
    else {
        jobject objPacket = create_packet(
                args, version, protocol, flags, source, sport, dest, dport, "", uid, 0);
        redirect = is_address_allowed(args, objPacket);
        allowed = (redirect != NULL);
        if (redirect != NULL && (*redirect->raddr == 0 || redirect->rport == 0))
            redirect = NULL;
    }

    // Handle allowed traffic
    if (allowed) {
        if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
            handle_icmp(args, pkt, length, payload, uid);
        else if (protocol == IPPROTO_UDP)
            handle_udp(args, pkt, length, payload, uid, redirect);
        else if (protocol == IPPROTO_TCP)
            handle_tcp(args, pkt, length, payload, uid, redirect);
    }
    else {
        if (protocol == IPPROTO_UDP)
            block_udp(args, pkt, length, payload, uid);
        log_android(ANDROID_LOG_WARN, "Address v%d p%d %s/%u syn %d not allowed",
                    version, protocol, dest, dport, syn);
    }

#ifdef PROFILE_EVENTS
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_EVENTS)
        log_android(ANDROID_LOG_WARN, "handle protocol %f", mselapsed);
#endif
}

jboolean handle_icmp(const struct arguments *args,
                     const uint8_t *pkt, size_t length,
                     const uint8_t *payload,
                     int uid) {
    // Get headers
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    struct icmp *icmp = (struct icmp *) payload;
    size_t icmplen = length - (payload - pkt);

    if (icmp->icmp_type != ICMP_ECHO) {
        log_android(ANDROID_LOG_WARN, "ICMP type %d code %d not supported",
                    icmp->icmp_type, icmp->icmp_code);
        return 0;
    }

    // Search session
    struct icmp_session *cur = icmp_session;
    while (cur != NULL &&
           !(!cur->stop && cur->version == version &&
             (version == 4 ? cur->saddr.ip4 == ip4->saddr &&
                             cur->daddr.ip4 == ip4->daddr
                           : memcmp(&cur->saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (version == 4) {
        inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
        inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &ip6->ip6_src, source, sizeof(source));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dest, sizeof(dest));
    }

    // Create new session if needed
    if (cur == NULL) {
        log_android(ANDROID_LOG_INFO, "ICMP new session from %s to %s", source, dest);

        // Register session
        struct icmp_session *i = malloc(sizeof(struct icmp_session));
        i->time = time(NULL);
        i->uid = uid;
        i->version = version;

        if (version == 4) {
            i->saddr.ip4 = (__be32) ip4->saddr;
            i->daddr.ip4 = (__be32) ip4->daddr;
        } else {
            memcpy(&i->saddr.ip6, &ip6->ip6_src, 16);
            memcpy(&i->daddr.ip6, &ip6->ip6_dst, 16);
        }

        i->id = icmp->icmp_id; // store original ID

        i->stop = 0;
        i->next = NULL;

        // Open UDP socket
        i->socket = open_icmp_socket(args, i);
        if (i->socket < 0) {
            free(i);
            return 0;
        }

        log_android(ANDROID_LOG_DEBUG, "ICMP socket %d id %x", i->socket, i->id);

        i->next = icmp_session;
        icmp_session = i;

        cur = i;
    }

    // Modify ID
    // http://lwn.net/Articles/443051/
    icmp->icmp_id = ~icmp->icmp_id;
    uint16_t csum = 0;
    if (version == 6) {
        // Untested
        struct ip6_hdr_pseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
    }
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = ~calc_checksum(csum, (uint8_t *) icmp, icmplen);

    log_android(ANDROID_LOG_INFO,
                "ICMP forward from tun %s to %s type %d code %d id %x seq %d data %d",
                source, dest,
                icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq, icmplen);

    cur->time = time(NULL);

    struct sockaddr_in server4;
    struct sockaddr_in6 server6;
    if (version == 4) {
        server4.sin_family = AF_INET;
        server4.sin_addr.s_addr = (__be32) ip4->daddr;
        server4.sin_port = 0;
    } else {
        server6.sin6_family = AF_INET6;
        memcpy(&server6.sin6_addr, &ip6->ip6_dst, 16);
        server6.sin6_port = 0;
    }

    // Send raw ICMP message
    if (sendto(cur->socket, icmp, (socklen_t) icmplen, MSG_NOSIGNAL,
               (const struct sockaddr *) (version == 4 ? &server4 : &server6),
               (socklen_t) (version == 4 ? sizeof(server4) : sizeof(server6))) != icmplen) {
        log_android(ANDROID_LOG_ERROR, "ICMP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            cur->stop = 1;
            return 0;
        }
    }

    return 1;
}

int has_udp_session(const struct arguments *args, const uint8_t *pkt, const uint8_t *payload) {
    // Get headers
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct udphdr *udphdr = (struct udphdr *) payload;

    if (ntohs(udphdr->dest) == 53 && !args->fwd53)
        return 1;

    // Search session
    struct udp_session *cur = udp_session;
    while (cur != NULL &&
           !(cur->version == version &&
             cur->source == udphdr->source && cur->dest == udphdr->dest &&
             (version == 4 ? cur->saddr.ip4 == ip4->saddr &&
                             cur->daddr.ip4 == ip4->daddr
                           : memcmp(&cur->saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    return (cur != NULL);
}

void block_udp(const struct arguments *args,
               const uint8_t *pkt, size_t length,
               const uint8_t *payload,
               int uid) {
    // Get headers
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct udphdr *udphdr = (struct udphdr *) payload;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (version == 4) {
        inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
        inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &ip6->ip6_src, source, sizeof(source));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dest, sizeof(dest));
    }

    log_android(ANDROID_LOG_INFO, "UDP blocked session from %s/%u to %s/%u",
                source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));

    // Register session
    struct udp_session *u = malloc(sizeof(struct udp_session));
    u->time = time(NULL);
    u->uid = uid;
    u->version = version;

    if (version == 4) {
        u->saddr.ip4 = (__be32) ip4->saddr;
        u->daddr.ip4 = (__be32) ip4->daddr;
    } else {
        memcpy(&u->saddr.ip6, &ip6->ip6_src, 16);
        memcpy(&u->daddr.ip6, &ip6->ip6_dst, 16);
    }

    u->source = udphdr->source;
    u->dest = udphdr->dest;
    u->state = UDP_BLOCKED;
    u->socket = -1;

    u->next = udp_session;
    udp_session = u;
}

jboolean handle_udp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect) {
    // Get headers
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct udphdr *udphdr = (struct udphdr *) payload;
    const uint8_t *data = payload + sizeof(struct udphdr);
    const size_t datalen = length - (data - pkt);

    // Search session
    struct udp_session *cur = udp_session;
    while (cur != NULL &&
           !(cur->version == version &&
             cur->source == udphdr->source && cur->dest == udphdr->dest &&
             (version == 4 ? cur->saddr.ip4 == ip4->saddr &&
                             cur->daddr.ip4 == ip4->daddr
                           : memcmp(&cur->saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (version == 4) {
        inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
        inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &ip6->ip6_src, source, sizeof(source));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dest, sizeof(dest));
    }

    if (cur != NULL && cur->state != UDP_ACTIVE) {
        log_android(ANDROID_LOG_INFO, "UDP ignore session from %s/%u to %s/%u state %d",
                    source, ntohs(udphdr->source), dest, ntohs(udphdr->dest), cur->state);
        return 0;
    }

    // Create new session if needed
    if (cur == NULL) {
        log_android(ANDROID_LOG_INFO, "UDP new session from %s/%u to %s/%u",
                    source, ntohs(udphdr->source), dest, ntohs(udphdr->dest));

        // Register session
        struct udp_session *u = malloc(sizeof(struct udp_session));
        u->time = time(NULL);
        u->uid = uid;
        u->version = version;

        if (version == 4) {
            u->saddr.ip4 = (__be32) ip4->saddr;
            u->daddr.ip4 = (__be32) ip4->daddr;
        } else {
            memcpy(&u->saddr.ip6, &ip6->ip6_src, 16);
            memcpy(&u->daddr.ip6, &ip6->ip6_dst, 16);
        }

        u->source = udphdr->source;
        u->dest = udphdr->dest;
        u->state = UDP_ACTIVE;
        u->next = NULL;

        // Open UDP socket
        u->socket = open_udp_socket(args, u);
        if (u->socket < 0) {
            free(u);
            return 0;
        }

        log_android(ANDROID_LOG_DEBUG, "UDP socket %d", u->socket);

        u->next = udp_session;
        udp_session = u;

        cur = u;
    }

    // Check for DNS
    if (ntohs(udphdr->dest) == 53) {
        char qname[DNS_QNAME_MAX + 1];
        uint16_t qtype;
        uint16_t qclass;
        if (get_dns_query(args, cur, data, datalen, &qtype, &qclass, qname) >= 0) {
            log_android(ANDROID_LOG_DEBUG,
                        "DNS query qtype %d qclass %d name %s",
                        qtype, qclass, qname);

            if (check_domain(args, cur, data, datalen, qclass, qtype, qname)) {
                // Log qname
                char name[DNS_QNAME_MAX + 40 + 1];
                sprintf(name, "qtype %d qname %s", qtype, qname);
                jobject objPacket = create_packet(
                        args, version, IPPROTO_UDP, "",
                        source, ntohs(cur->source), dest, ntohs(cur->dest),
                        name, 0, 0);
                log_packet(args, objPacket);

                // Session done
                cur->state = UDP_FINISHING;
                return 0;
            }
        }
    }

    // Check for DHCP (tethering)
    if (ntohs(udphdr->source) == 68 || ntohs(udphdr->dest) == 67) {
        if (check_dhcp(args, cur, data, datalen) >= 0)
            return 1;
    }

    log_android(ANDROID_LOG_INFO, "UDP forward from tun %s/%u to %s/%u data %d",
                source, ntohs(udphdr->source), dest, ntohs(udphdr->dest), datalen);

    cur->time = time(NULL);

    int rversion;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    if (redirect == NULL) {
        rversion = cur->version;
        if (cur->version == 4) {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) cur->daddr.ip4;
            addr4.sin_port = cur->dest;
        } else {
            addr6.sin6_family = AF_INET6;
            memcpy(&addr6.sin6_addr, &cur->daddr.ip6, 16);
            addr6.sin6_port = cur->dest;
        }
    } else {
        rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
        log_android(ANDROID_LOG_WARN, "UDP%d redirect to %s/%u",
                    rversion, redirect->raddr, redirect->rport);

        if (rversion == 4) {
            addr4.sin_family = AF_INET;
            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
            addr4.sin_port = htons(redirect->rport);
        }
        else {
            addr6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
            addr6.sin6_port = htons(redirect->rport);
        }
    }

    if (sendto(cur->socket, data, (socklen_t) datalen, MSG_NOSIGNAL,
               (const struct sockaddr *) (rversion == 4 ? &addr4 : &addr6),
               (socklen_t) (version == 4 ? sizeof(addr4) : sizeof(addr6))) != datalen) {
        log_android(ANDROID_LOG_ERROR, "UDP sendto error %d: %s", errno, strerror(errno));
        if (errno != EINTR && errno != EAGAIN) {
            cur->state = UDP_FINISHING;
            return 0;
        }
    }

    return 1;
}

int get_dns_query(const struct arguments *args, const struct udp_session *u,
                  const uint8_t *data, const size_t datalen,
                  uint16_t *qtype, uint16_t *qclass, char *qname) {
    if (datalen < sizeof(struct dns_header) + 1) {
        log_android(ANDROID_LOG_WARN, "DNS query length %d", datalen);
        return -1;
    }

    // Check if standard DNS query
    // TODO multiple qnames
    const struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    if (dns->qr == 0 && dns->opcode == 0 && qcount > 0) {
        if (qcount > 1)
            log_android(ANDROID_LOG_WARN, "DNS query qcount %d", qcount);

        // http://tools.ietf.org/html/rfc1035
        int off = get_qname(data, datalen, sizeof(struct dns_header), qname);
        if (off > 0 && off + 4 == datalen) {
            *qtype = ntohs(*((uint16_t *) (data + off)));
            *qclass = ntohs(*((uint16_t *) (data + off + 2)));
            return 0;
        }
        else
            log_android(ANDROID_LOG_WARN, "DNS query invalid off %d datalen %d", off, datalen);
    }

    return -1;
}

int check_domain(const struct arguments *args, const struct udp_session *u,
                 const uint8_t *data, const size_t datalen,
                 uint16_t qclass, uint16_t qtype, const char *name) {

    if (qclass == DNS_QCLASS_IN &&
        (qtype == DNS_QTYPE_A || qtype == DNS_QTYPE_AAAA) &&
        is_domain_blocked(args, name)) {

        log_android(ANDROID_LOG_INFO, "DNS query type %d name %s blocked", qtype, name);

        // Build response
        size_t rlen = datalen + sizeof(struct dns_rr) + (qtype == DNS_QTYPE_A ? 4 : 16);
        uint8_t *response = malloc(rlen);

        // Copy header & query
        memcpy(response, data, datalen);

        // Modify copied header
        struct dns_header *rh = (struct dns_header *) response;
        rh->qr = 1;
        rh->aa = 0;
        rh->tc = 0;
        rh->rd = 0;
        rh->ra = 0;
        rh->z = 0;
        rh->ad = 0;
        rh->cd = 0;
        rh->rcode = 0;
        rh->ans_count = htons(1);
        rh->auth_count = 0;
        rh->add_count = 0;

        // Build answer
        struct dns_rr *answer = (struct dns_rr *) (response + datalen);
        answer->qname_ptr = htons(sizeof(struct dns_header) | 0xC000);
        answer->qtype = htons(qtype);
        answer->qclass = htons(qclass);
        answer->ttl = htonl(DNS_TTL);
        answer->rdlength = htons(qtype == DNS_QTYPE_A ? 4 : 16);

        // Add answer address
        uint8_t *addr = response + datalen + sizeof(struct dns_rr);
        if (qtype == DNS_QTYPE_A)
            inet_pton(AF_INET, "127.0.0.1", addr);
        else
            inet_pton(AF_INET6, "::1", addr);

        // Experiment
        rlen = datalen;
        rh->rcode = 3; // NXDOMAIN
        rh->ans_count = 0;

        // Send response
        if (write_udp(args, u, response, rlen) < 0)
            log_android(ANDROID_LOG_WARN, "UDP DNS write error %d: %s", errno, strerror(errno));

        free(response);

        return 1;
    }

    return 0;
}

int check_dhcp(const struct arguments *args, const struct udp_session *u,
               const uint8_t *data, const size_t datalen) {

    // This is untested
    // Android routing of DHCP is erroneous

    log_android(ANDROID_LOG_WARN, "DHCP check");

    if (datalen < sizeof(struct dhcp_packet)) {
        log_android(ANDROID_LOG_WARN, "DHCP packet size %d", datalen);
        return -1;
    }

    const struct dhcp_packet *request = (struct dhcp_packet *) data;

    if (ntohl(request->option_format) != DHCP_OPTION_MAGIC_NUMBER) {
        log_android(ANDROID_LOG_WARN, "DHCP invalid magic %x", request->option_format);
        return -1;
    }

    if (request->htype != 1 || request->hlen != 6) {
        log_android(ANDROID_LOG_WARN, "DHCP unknown hardware htype %d hlen %d",
                    request->htype, request->hlen);
        return -1;
    }

    log_android(ANDROID_LOG_WARN, "DHCP opcode", request->opcode);

    // Discover: source 0.0.0.0:68 destination 255.255.255.255:67
    // Offer: source 10.1.10.1:67 destination 255.255.255.255:68
    // Request: source 0.0.0.0:68 destination 255.255.255.255:67
    // Ack: source: 10.1.10.1 destination: 255.255.255.255

    if (request->opcode == 1) { // Discover/request
        struct dhcp_packet *response = calloc(500, 1);

        // Hack
        inet_pton(AF_INET, "10.1.10.1", &u->saddr);

        /*
        Discover:
            DHCP option 53: DHCP Discover
            DHCP option 50: 192.168.1.100 requested
            DHCP option 55: Parameter Request List:
            Request Subnet Mask (1), Router (3), Domain Name (15), Domain Name Server (6)

        Request
            DHCP option 53: DHCP Request
            DHCP option 50: 192.168.1.100 requested
            DHCP option 54: 192.168.1.1 DHCP server.
        */

        memcpy(response, request, sizeof(struct dhcp_packet));
        response->opcode = (uint8_t) (request->siaddr == 0 ? 2 /* Offer */ : /* Ack */ 4);
        response->secs = 0;
        response->flags = 0;
        memset(&response->ciaddr, 0, sizeof(response->ciaddr));
        inet_pton(AF_INET, "10.1.10.2", &response->yiaddr);
        inet_pton(AF_INET, "10.1.10.1", &response->siaddr);
        memset(&response->giaddr, 0, sizeof(response->giaddr));

        // https://tools.ietf.org/html/rfc2132
        uint8_t *options = (uint8_t *) (response + sizeof(struct dhcp_packet));

        int idx = 0;
        *(options + idx++) = 53; // Message type
        *(options + idx++) = 1;
        *(options + idx++) = (uint8_t) (request->siaddr == 0 ? 2 : 5);
        /*
             1     DHCPDISCOVER
             2     DHCPOFFER
             3     DHCPREQUEST
             4     DHCPDECLINE
             5     DHCPACK
             6     DHCPNAK
             7     DHCPRELEASE
             8     DHCPINFORM
         */

        *(options + idx++) = 1; // subnet mask
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "255.255.255.0", options + idx);
        idx += 4;

        *(options + idx++) = 3; // gateway
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "10.1.10.1", options + idx);
        idx += 4;

        *(options + idx++) = 51; // lease time
        *(options + idx++) = 4; // quad
        *((uint32_t *) (options + idx)) = 3600;
        idx += 4;

        *(options + idx++) = 54; // DHCP
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "10.1.10.1", options + idx);
        idx += 4;

        *(options + idx++) = 6; // DNS
        *(options + idx++) = 4; // IP4 length
        inet_pton(AF_INET, "8.8.8.8", options + idx);
        idx += 4;

        *(options + idx++) = 255; // End

        /*
            DHCP option 53: DHCP Offer
            DHCP option 1: 255.255.255.0 subnet mask
            DHCP option 3: 192.168.1.1 router
            DHCP option 51: 86400s (1 day) IP address lease time
            DHCP option 54: 192.168.1.1 DHCP server
            DHCP option 6: DNS servers 9.7.10.15
         */

        write_udp(args, u, (uint8_t *) response, 500);

        free(response);
    }

    return 0;
}

jboolean handle_tcp(const struct arguments *args,
                    const uint8_t *pkt, size_t length,
                    const uint8_t *payload,
                    int uid, struct allowed *redirect) {
    // Get headers
    const uint8_t version = (*pkt) >> 4;
    const struct iphdr *ip4 = (struct iphdr *) pkt;
    const struct ip6_hdr *ip6 = (struct ip6_hdr *) pkt;
    const struct tcphdr *tcphdr = (struct tcphdr *) payload;
    const uint8_t tcpoptlen = (uint8_t) ((tcphdr->doff - 5) * 4);
    const uint8_t *data = payload + sizeof(struct tcphdr) + tcpoptlen;
    const uint16_t datalen = (const uint16_t) (length - (data - pkt));

    // Search session
    struct tcp_session *cur = tcp_session;
    while (cur != NULL &&
           !(cur->version == version &&
             cur->source == tcphdr->source && cur->dest == tcphdr->dest &&
             (version == 4 ? cur->saddr.ip4 == ip4->saddr &&
                             cur->daddr.ip4 == ip4->daddr
                           : memcmp(&cur->saddr.ip6, &ip6->ip6_src, 16) == 0 &&
                             memcmp(&cur->daddr.ip6, &ip6->ip6_dst, 16) == 0)))
        cur = cur->next;

    // Prepare logging
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    if (version == 4) {
        inet_ntop(AF_INET, &ip4->saddr, source, sizeof(source));
        inet_ntop(AF_INET, &ip4->daddr, dest, sizeof(dest));
    } else {
        inet_ntop(AF_INET6, &ip6->ip6_src, source, sizeof(source));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dest, sizeof(dest));
    }

    char flags[10];
    int flen = 0;
    if (tcphdr->syn)
        flags[flen++] = 'S';
    if (tcphdr->ack)
        flags[flen++] = 'A';
    if (tcphdr->fin)
        flags[flen++] = 'F';
    if (tcphdr->rst)
        flags[flen++] = 'R';
    flags[flen] = 0;

    char packet[250];
    sprintf(packet,
            "TCP %s %s/%u > %s/%u seq %u ack %u data %u win %u uid %d",
            flags,
            source, ntohs(tcphdr->source),
            dest, ntohs(tcphdr->dest),
            ntohl(tcphdr->seq) - (cur == NULL ? 0 : cur->remote_start),
            tcphdr->ack ? ntohl(tcphdr->ack_seq) - (cur == NULL ? 0 : cur->local_start) : 0,
            datalen, ntohs(tcphdr->window), uid);
    log_android(ANDROID_LOG_DEBUG, packet);

    // Check session
    if (cur == NULL) {
        if (tcphdr->syn) {
            log_android(ANDROID_LOG_INFO, "%s new session", packet);

            // Register session
            struct tcp_session *syn = malloc(sizeof(struct tcp_session));
            syn->time = time(NULL);
            syn->uid = uid;
            syn->version = version;
            syn->recv_window = TCP_RECV_WINDOW;
            syn->send_window = ntohs(tcphdr->window);
            syn->remote_seq = ntohl(tcphdr->seq); // ISN remote
            syn->local_seq = (uint32_t) rand(); // ISN local
            syn->remote_start = syn->remote_seq;
            syn->local_start = syn->local_seq;

            if (version == 4) {
                syn->saddr.ip4 = (__be32) ip4->saddr;
                syn->daddr.ip4 = (__be32) ip4->daddr;
            } else {
                memcpy(&syn->saddr.ip6, &ip6->ip6_src, 16);
                memcpy(&syn->daddr.ip6, &ip6->ip6_dst, 16);
            }

            syn->source = tcphdr->source;
            syn->dest = tcphdr->dest;
            syn->state = TCP_LISTEN;
            syn->forward = NULL;
            syn->next = NULL;

            if (datalen) {
                log_android(ANDROID_LOG_WARN, "%s SYN data", packet);
                syn->forward = malloc(sizeof(struct segment));
                syn->forward->seq = syn->remote_seq;
                syn->forward->len = datalen;
                syn->forward->psh = tcphdr->psh;
                syn->forward->data = malloc(datalen);
                memcpy(syn->forward->data, data, datalen);
                syn->forward->next = NULL;
            }

            // Open socket
            syn->socket = open_tcp_socket(args, syn, redirect);
            if (syn->socket < 0) {
                // Remote might retry
                free(syn);
                return 0;
            }

            log_android(ANDROID_LOG_DEBUG, "TCP socket %d lport %d",
                        syn->socket, get_local_port(syn->socket));

            syn->next = tcp_session;
            tcp_session = syn;
        }
        else {
            log_android(ANDROID_LOG_WARN, "%s unknown session", packet);

            struct tcp_session rst;
            memset(&rst, 0, sizeof(struct tcp_session));
            rst.version = 4;
            rst.recv_window = TCP_RECV_WINDOW;
            rst.local_seq = ntohl(tcphdr->ack_seq);
            rst.remote_seq = ntohl(tcphdr->seq) + datalen + (tcphdr->fin ? 1 : 0);

            if (version == 4) {
                rst.saddr.ip4 = (__be32) ip4->saddr;
                rst.daddr.ip4 = (__be32) ip4->daddr;
            } else {
                memcpy(&rst.saddr.ip6, &ip6->ip6_src, 16);
                memcpy(&rst.daddr.ip6, &ip6->ip6_dst, 16);
            }

            rst.source = tcphdr->source;
            rst.dest = tcphdr->dest;
            rst.socket = -1;

            write_rst(args, &rst);
            return 0;
        }
    }
    else {
        char session[250];
        sprintf(session,
                "%s %s loc %u rem %u",
                packet,
                strstate(cur->state),
                cur->local_seq - cur->local_start,
                cur->remote_seq - cur->remote_start);

        // Session found
        if (cur->state == TCP_CLOSING || cur->state == TCP_CLOSE) {
            log_android(ANDROID_LOG_WARN, "%s was closed", session);
            write_rst(args, cur);
            return 0;
        }
        else {
            int oldstate = cur->state;
            uint32_t oldlocal = cur->local_seq;
            uint32_t oldremote = cur->remote_seq;

            log_android(ANDROID_LOG_DEBUG, "%s handling", session);

            cur->time = time(NULL);
            cur->send_window = ntohs(tcphdr->window);

            // Do not change the order of the conditions

            // Queue data to forward
            if (datalen) {
                if (cur->socket < 0) {
                    log_android(ANDROID_LOG_ERROR, "%s data while remote closed", session);
                    write_rst(args, cur);
                    return 0;
                }
                forward_tcp(args, tcphdr, session, cur, data, datalen);
            }

            if (tcphdr->rst /* +ACK */) {
                // No sequence check
                // TODO half-duplex close sequence
                // http://tools.ietf.org/html/rfc1122#page-87
                log_android(ANDROID_LOG_WARN, "%s received reset", session);
                cur->state = TCP_CLOSING;
                return 0;
            }
            else {
                if (!tcphdr->ack || ntohl(tcphdr->ack_seq) == cur->local_seq) {
                    if (tcphdr->syn) {
                        log_android(ANDROID_LOG_WARN, "%s repeated SYN", session);
                        // The socket is probably not opened yet

                    } else if (tcphdr->fin /* +ACK */) {
                        if (cur->state == TCP_ESTABLISHED) {
                            if (cur->socket < 0) {
                                cur->remote_seq++; // remote FIN
                                if (write_fin_ack(args, cur) >= 0) {
                                    log_android(ANDROID_LOG_WARN, "%s finished closed", session);
                                    cur->local_seq++; // local FIN
                                    cur->state = TCP_LAST_ACK;
                                }
                            }
                            else {
                                log_android(ANDROID_LOG_WARN, "%s socket close wait", session);
                                cur->state = TCP_CLOSE_WAIT;
                                if (cur->send_window == 0)
                                    log_android(ANDROID_LOG_WARN, "%s FIN send window 0", session);
                            }
                        } else if (cur->state == TCP_CLOSE_WAIT)
                            log_android(ANDROID_LOG_WARN, "%s repeated FIN", session);
                        else {
                            // Could be repeated FIN
                            log_android(ANDROID_LOG_ERROR, "%s invalid FIN", session);
                            return 0;
                        }

                    } else if (tcphdr->ack) {
                        if (cur->state == TCP_SYN_RECV)
                            cur->state = TCP_ESTABLISHED;
                        else if (cur->state == TCP_ESTABLISHED) {
                            // Do nothing
                        } else if (cur->state == TCP_LAST_ACK)
                            cur->state = TCP_CLOSING;
                        else {
                            log_android(ANDROID_LOG_ERROR, "%s invalid state", session);
                            return 0;
                        }
                    }

                    else {
                        log_android(ANDROID_LOG_ERROR, "%s unknown packet", session);
                        return 0;
                    }
                }
                else {
                    if (compare_u16(ntohl(tcphdr->ack_seq), cur->local_seq) < 0) {
                        log_android(ANDROID_LOG_WARN, "%s previous ACK", session);
                        return 1;
                    }
                    else {
                        log_android(ANDROID_LOG_ERROR, "%s future ACK", session);
                        return 0;
                    }
                }
            }

            if (cur->state != oldstate ||
                cur->local_seq != oldlocal ||
                cur->remote_seq != oldremote)
                log_android(ANDROID_LOG_INFO, "%s > %s loc %d rem %d",
                            session,
                            strstate(cur->state),
                            cur->local_seq - cur->local_start,
                            cur->remote_seq - cur->remote_start);
        }
    }

    return 1;
}

void forward_tcp(const struct arguments *args,
                 const struct tcphdr *tcphdr,
                 const char *session, struct tcp_session *cur,
                 const uint8_t *data, uint16_t datalen) {
    uint32_t seq = ntohl(tcphdr->seq);
    if (compare_u16(seq, cur->remote_seq) < 0)
        log_android(ANDROID_LOG_WARN, "%s already forwarded", session);
    else {
        struct segment *p = NULL;
        struct segment *s = cur->forward;
        while (s != NULL && compare_u16(s->seq, seq) < 0) {
            p = s;
            s = s->next;
        }

        if (s == NULL || compare_u16(s->seq, seq) > 0) {
            log_android(ANDROID_LOG_DEBUG, "%s queuing %u...%u", session, seq, seq + datalen);
            struct segment *n = malloc(sizeof(struct segment));
            n->seq = seq;
            n->len = datalen;
            n->psh = tcphdr->psh;
            n->data = malloc(datalen);
            memcpy(n->data, data, datalen);
            n->next = s;
            if (p == NULL)
                cur->forward = n;
            else
                p->next = n;
        }
        else if (s != NULL && s->seq == seq) {
            if (s->len == datalen)
                log_android(ANDROID_LOG_WARN, "%s segment already queued %u..%u",
                            session, s->seq, s->seq + s->len);
            else if (s->len < datalen) {
                log_android(ANDROID_LOG_WARN, "%s segment smaller %u..%u > %u",
                            session, s->seq, s->seq + s->len, s->seq + datalen);
                free(s->data);
                s->data = malloc(datalen);
                memcpy(s->data, data, datalen);
            }
            else
                log_android(ANDROID_LOG_ERROR, "%s segment larger %u..%u < %u",
                            session, s->seq, s->seq + s->len, s->seq + datalen);
        }
    }
}

int open_icmp_socket(const struct arguments *args, const struct icmp_session *cur) {
    int sock;

    // Get UDP socket
    sock = socket(cur->version == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        log_android(ANDROID_LOG_ERROR, "ICMP socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect socket
    if (protect_socket(args, sock) < 0)
        return -1;

    return sock;
}

int open_udp_socket(const struct arguments *args, const struct udp_session *cur) {
    int sock;

    // Get UDP socket
    sock = socket(cur->version == 4 ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        log_android(ANDROID_LOG_ERROR, "UDP socket error %d: %s", errno, strerror(errno));
        return -1;
    }

    // Protect socket
    if (protect_socket(args, sock) < 0)
        return -1;

    // Check for broadcast/multicast
    if (cur->version == 4) {
        uint32_t broadcast4 = INADDR_BROADCAST;
        if (memcmp(&cur->daddr.ip4, &broadcast4, sizeof(broadcast4)) == 0) {
            log_android(ANDROID_LOG_WARN, "UDP4 broadcast");
            int on = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)))
                log_android(ANDROID_LOG_ERROR, "UDP setsockopt SO_BROADCAST error %d: %s",
                            errno, strerror(errno));
        }
    } else {
        // http://man7.org/linux/man-pages/man7/ipv6.7.html
        if (*((uint8_t *) &cur->daddr.ip6) == 0xFF) {
            log_android(ANDROID_LOG_WARN, "UDP6 broadcast");

            int loop = 1; // true
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)))
                log_android(ANDROID_LOG_ERROR,
                            "UDP setsockopt IPV6_MULTICAST_LOOP error %d: %s",
                            errno, strerror(errno));

            int ttl = -1; // route default
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)))
                log_android(ANDROID_LOG_ERROR,
                            "UDP setsockopt IPV6_MULTICAST_HOPS error %d: %s",
                            errno, strerror(errno));

            struct ipv6_mreq mreq6;
            memcpy(&mreq6.ipv6mr_multiaddr, &cur->daddr.ip6, sizeof(struct in6_addr));
            mreq6.ipv6mr_interface = INADDR_ANY;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)))
                log_android(ANDROID_LOG_ERROR,
                            "UDP setsockopt IPV6_ADD_MEMBERSHIP error %d: %s",
                            errno, strerror(errno));
        }
    }

    return sock;
}

int open_tcp_socket(const struct arguments *args,
                    const struct tcp_session *cur, const struct allowed *redirect) {
    int sock;

    // Get TCP socket
    // TODO socket options?
    if ((sock = socket(cur->version == 4 ? PF_INET : PF_INET6, SOCK_STREAM, 0)) < 0) {
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

    // Build target address
    int rversion;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    if (redirect == NULL) {
        rversion = cur->version;
        if (cur->version == 4) {
            addr4.sin_family = AF_INET;
            addr4.sin_addr.s_addr = (__be32) cur->daddr.ip4;
            addr4.sin_port = cur->dest;
        } else {
            addr6.sin6_family = AF_INET6;
            memcpy(&addr6.sin6_addr, &cur->daddr.ip6, 16);
            addr6.sin6_port = cur->dest;
        }
    } else {
        rversion = (strstr(redirect->raddr, ":") == NULL ? 4 : 6);
        log_android(ANDROID_LOG_WARN, "TCP%d redirect to %s/%u",
                    rversion, redirect->raddr, redirect->rport);

        if (rversion == 4) {
            addr4.sin_family = AF_INET;
            inet_pton(AF_INET, redirect->raddr, &addr4.sin_addr);
            addr4.sin_port = htons(redirect->rport);
        }
        else {
            addr6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, redirect->raddr, &addr6.sin6_addr);
            addr6.sin6_port = htons(redirect->rport);
        }
    }

    // Initiate connect
    int err = connect(sock,
                      (const struct sockaddr *) (rversion == 4 ? &addr4 : &addr6),
                      (socklen_t) (cur->version == 4
                                   ? sizeof(struct sockaddr_in)
                                   : sizeof(struct sockaddr_in6)));
    if (err < 0 && errno != EINPROGRESS) {
        log_android(ANDROID_LOG_ERROR, "connect error %d: %s", errno, strerror(errno));
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

int write_syn_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 1, 1, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_ack(const struct arguments *args, struct tcp_session *cur, size_t bytes) {
    if (write_tcp(args, cur, NULL, 0, bytes, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length) {
    if (write_tcp(args, cur, buffer, length, 0, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_fin_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 0, 1, 1, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

void write_rst(const struct arguments *args, struct tcp_session *cur) {
    write_tcp(args, cur, NULL, 0, 0, 0, 0, 0, 1);
    if (cur->state != TCP_CLOSE)
        cur->state = TCP_CLOSING;
}

// TODO common UDP/TCP

ssize_t write_icmp(const struct arguments *args, const struct icmp_session *cur,
                   uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct icmp *icmp = (struct icmp *) data;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
    if (cur->version == 4) {
        len = sizeof(struct iphdr) + datalen;
        buffer = malloc(len);
        struct iphdr *ip4 = (struct iphdr *) buffer;
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr), data, datalen);

        // Build IP4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_ICMP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Calculate IP4 checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));
    }
    else {
        len = sizeof(struct ip6_hdr) + datalen;
        buffer = malloc(len);
        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
        if (datalen)
            memcpy(buffer + sizeof(struct ip6_hdr), data, datalen);

        // Build IP6 header
        memset(ip6, 0, sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
        ip6->ip6_ctlun.ip6_un2_vfc = IPV6_VERSION;
        memcpy(&(ip6->ip6_src), &cur->daddr.ip6, 16);
        memcpy(&(ip6->ip6_dst), &cur->saddr.ip6, 16);
    }

    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->saddr.ip4 : &cur->saddr.ip6, source, sizeof(source));
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->daddr.ip4 : &cur->daddr.ip6, dest, sizeof(dest));

    // Send raw ICMP message
    log_android(ANDROID_LOG_DEBUG,
                "ICMP sending to tun %d from %s to %s data %u type %d code %d id %x seq %d",
                args->tun, dest, source, datalen,
                icmp->icmp_type, icmp->icmp_code, icmp->icmp_id, icmp->icmp_seq);

    ssize_t res = write(args->tun, buffer, len);

    // Write PCAP record
    if (res >= 0) {
        if (pcap_file != NULL)
            write_pcap_rec(buffer, (size_t) res);
    }
    else
        log_android(ANDROID_LOG_WARN, "ICMP write error %d: %s", errno, strerror(errno));

    free(buffer);

    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "write %d wrote %d", res, len);
        return -1;
    }

    return res;
}

ssize_t write_udp(const struct arguments *args, const struct udp_session *cur,
                  uint8_t *data, size_t datalen) {
    size_t len;
    u_int8_t *buffer;
    struct udphdr *udp;
    uint16_t csum;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
    if (cur->version == 4) {
        len = sizeof(struct iphdr) + sizeof(struct udphdr) + datalen;
        buffer = malloc(len);
        struct iphdr *ip4 = (struct iphdr *) buffer;
        udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr) + sizeof(struct udphdr), data, datalen);

        // Build IP4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_UDP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Calculate IP4 checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        // Calculate UDP4 checksum
        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct udphdr) + datalen);

        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    }
    else {
        len = sizeof(struct ip6_hdr) + sizeof(struct udphdr) + datalen;
        buffer = malloc(len);
        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
        udp = (struct udphdr *) (buffer + sizeof(struct ip6_hdr));
        if (datalen)
            memcpy(buffer + sizeof(struct ip6_hdr) + sizeof(struct udphdr), data, datalen);

        // Build IP6 header
        memset(ip6, 0, sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = 0;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
        ip6->ip6_ctlun.ip6_un2_vfc = IPV6_VERSION;
        memcpy(&(ip6->ip6_src), &cur->daddr.ip6, 16);
        memcpy(&(ip6->ip6_dst), &cur->saddr.ip6, 16);

        // Calculate UDP6 checksum
        struct ip6_hdr_pseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
    }

    // Build UDP header
    memset(udp, 0, sizeof(struct udphdr));
    udp->source = cur->dest;
    udp->dest = cur->source;
    udp->len = htons(sizeof(struct udphdr) + datalen);

    // Continue checksum
    csum = calc_checksum(csum, (uint8_t *) udp, sizeof(struct udphdr));
    csum = calc_checksum(csum, data, datalen);
    udp->check = ~csum;

    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->saddr.ip4 : &cur->saddr.ip6, source, sizeof(source));
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->daddr.ip4 : &cur->daddr.ip6, dest, sizeof(dest));

    // Send packet
    log_android(ANDROID_LOG_DEBUG,
                "UDP sending to tun %d from %s/%u to %s/%u data %u",
                args->tun, dest, ntohs(cur->dest), source, ntohs(cur->source), len);

    ssize_t res = write(args->tun, buffer, len);

    // Write PCAP record
    if (res >= 0) {
        if (pcap_file != NULL)
            write_pcap_rec(buffer, (size_t) res);
    }
    else
        log_android(ANDROID_LOG_WARN, "UDP write error %d: %s", errno, strerror(errno));

    free(buffer);

    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "write %d wrote %d", res, len);
        return -1;
    }

    return res;
}

ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen, size_t confirm,
                  int syn, int ack, int fin, int rst) {
    size_t len;
    u_int8_t *buffer;
    struct tcphdr *tcp;
    uint16_t csum;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    // Build packet
    int optlen = (syn ? 4 : 0);
    uint8_t *options;
    if (cur->version == 4) {
        len = sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen + datalen;
        buffer = malloc(len);
        struct iphdr *ip4 = (struct iphdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        options = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (datalen)
            memcpy(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        // Build IP4 header
        memset(ip4, 0, sizeof(struct iphdr));
        ip4->version = 4;
        ip4->ihl = sizeof(struct iphdr) >> 2;
        ip4->tot_len = htons(len);
        ip4->ttl = IPDEFTTL;
        ip4->protocol = IPPROTO_TCP;
        ip4->saddr = cur->daddr.ip4;
        ip4->daddr = cur->saddr.ip4;

        // Calculate IP4 checksum
        ip4->check = ~calc_checksum(0, (uint8_t *) ip4, sizeof(struct iphdr));

        // Calculate TCP4 checksum
        struct ippseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ippseudo));
        pseudo.ippseudo_src.s_addr = (__be32) ip4->saddr;
        pseudo.ippseudo_dst.s_addr = (__be32) ip4->daddr;
        pseudo.ippseudo_p = ip4->protocol;
        pseudo.ippseudo_len = htons(sizeof(struct tcphdr) + optlen + datalen);

        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ippseudo));
    }
    else {
        len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen + datalen;
        buffer = malloc(len);
        struct ip6_hdr *ip6 = (struct ip6_hdr *) buffer;
        tcp = (struct tcphdr *) (buffer + sizeof(struct ip6_hdr));
        options = buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
        if (datalen)
            memcpy(buffer + sizeof(struct ip6_hdr) + sizeof(struct tcphdr) + optlen, data, datalen);

        // Build IP6 header
        memset(ip6, 0, sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len - sizeof(struct ip6_hdr));
        ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
        ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = IPDEFTTL;
        ip6->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(&(ip6->ip6_src), &cur->daddr.ip6, 16);
        memcpy(&(ip6->ip6_dst), &cur->saddr.ip6, 16);

        // Calculate TCP6 checksum
        struct ip6_hdr_pseudo pseudo;
        memset(&pseudo, 0, sizeof(struct ip6_hdr_pseudo));
        memcpy(&pseudo.ip6ph_src, &ip6->ip6_dst, 16);
        memcpy(&pseudo.ip6ph_dst, &ip6->ip6_src, 16);
        pseudo.ip6ph_len = ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
        pseudo.ip6ph_nxt = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        csum = calc_checksum(0, (uint8_t *) &pseudo, sizeof(struct ip6_hdr_pseudo));
    }


    // Build TCP header
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->source = cur->dest;
    tcp->dest = cur->source;
    tcp->seq = htonl(cur->local_seq);
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq + confirm));
    tcp->doff = (__u16) ((sizeof(struct tcphdr) + optlen) >> 2);
    tcp->syn = (__u16) syn;
    tcp->ack = (__u16) ack;
    tcp->fin = (__u16) fin;
    tcp->rst = (__u16) rst;
    tcp->window = htons(cur->recv_window);
    tcp->urg_ptr;

    if (!tcp->ack)
        tcp->ack_seq = 0;

    // TCP options
    if (syn) {
        *(options) = 2; // MSS
        *(options + 1) = 4; // total option length
        *((uint16_t *) (options + 2)) = // option value
                htons(TUN_MAXMSG - sizeof(struct ip6_hdr) - sizeof(struct tcphdr) - 4);
    }

    // Continue checksum
    csum = calc_checksum(csum, (uint8_t *) tcp, sizeof(struct tcphdr));
    csum = calc_checksum(csum, options, (size_t) optlen);
    csum = calc_checksum(csum, data, datalen);
    tcp->check = ~csum;

    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->saddr.ip4 : &cur->saddr.ip6, source, sizeof(source));
    inet_ntop(cur->version == 4 ? AF_INET : AF_INET6,
              cur->version == 4 ? &cur->daddr.ip4 : &cur->daddr.ip6, dest, sizeof(dest));

    // Send packet
    log_android(ANDROID_LOG_DEBUG,
                "TCP sending%s%s%s%s to tun %s/%u seq %u ack %u data %u confirm %u",
                (tcp->syn ? " SYN" : ""),
                (tcp->ack ? " ACK" : ""),
                (tcp->fin ? " FIN" : ""),
                (tcp->rst ? " RST" : ""),
                dest, ntohs(tcp->dest),
                ntohl(tcp->seq) - cur->local_start,
                ntohl(tcp->ack_seq) - cur->remote_start,
                datalen, confirm);

    ssize_t res = write(args->tun, buffer, len);

    // Write pcap record
    if (res >= 0) {
        if (pcap_file != NULL)
            write_pcap_rec(buffer, (size_t) res);
    } else
        log_android(ANDROID_LOG_ERROR, "TCP write%s%s%s%s data %d confirm %d error %d: %s",
                    (tcp->syn ? " SYN" : ""),
                    (tcp->ack ? " ACK" : ""),
                    (tcp->fin ? " FIN" : ""),
                    (tcp->rst ? " RST" : ""),
                    datalen, confirm,
                    errno, strerror((errno)));

    free(buffer);

    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "TCP write %d wrote %d", res, len);
        return -1;
    }

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

#ifdef PROFILE_UID
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    // Get proc file name
    char *fn = NULL;
    if (protocol == IPPROTO_ICMP && version == 4)
        fn = "/proc/net/icmp";
    else if (protocol == IPPROTO_ICMPV6 && version == 6)
        fn = "/proc/net/icmp6";
    else if (protocol == IPPROTO_TCP)
        fn = (version == 4 ? "/proc/net/tcp" : "/proc/net/tcp6");
    else if (protocol == IPPROTO_UDP)
        fn = (version == 4 ? "/proc/net/udp" : "/proc/net/udp6");
    else
        return uid;

    if (dump) {
        char source[INET6_ADDRSTRLEN + 1];
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
                    char source[INET6_ADDRSTRLEN + 1];
                    inet_ntop(version == 4 ? AF_INET : AF_INET6,
                              version == 4 ? addr4 : addr6,
                              source, sizeof(source));
                    log_android(ANDROID_LOG_INFO, "%s/%u %d %s", source, port, u, line);
                }

                if (port == sport) {
                    uid = u;
                    if (memcmp(version == 4 ? addr4 : addr6, saddr, version == 4 ? 4 : 16) == 0)
                        break;
                }
            } else
                log_android(ANDROID_LOG_ERROR, "Invalid field #%d: %s", fields, line);
        }
    }

    if (fclose(fd))
        log_android(ANDROID_LOG_ERROR, "fclose %s error %d: %s", fn, errno, strerror(errno));

#ifdef PROFILE_UID
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_UID)
        log_android(ANDROID_LOG_WARN, "get uid ip %f", mselapsed);
#endif

    return uid;
}

static jmethodID midProtect = NULL;

int protect_socket(const struct arguments *args, int socket) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    if (midProtect == NULL)
        midProtect = jniGetMethodID(args->env, cls, "protect", "(I)Z");

    jboolean isProtected = (*args->env)->CallBooleanMethod(
            args->env, args->instance, midProtect, socket);
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

jmethodID jniGetMethodID(JNIEnv *env, jclass cls, const char *name, const char *signature) {
    jmethodID method = (*env)->GetMethodID(env, cls, name, signature);
    if (method == NULL) {
        log_android(ANDROID_LOG_ERROR, "Method %s %s not found", name, signature);
        jniCheckException(env);
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

int sdk_int(JNIEnv *env) {
    jclass clsVersion = jniFindClass(env, "android/os/Build$VERSION");
    jfieldID fid = (*env)->GetStaticFieldID(env, clsVersion, "SDK_INT", "I");
    return (*env)->GetStaticIntField(env, clsVersion, fid);
}

typedef int (*PFN_SYS_PROP_GET)(const char *, char *);

int __system_property_get(JNIEnv *env, const char *name, char *value) {
    static PFN_SYS_PROP_GET __real_system_property_get = NULL;
    if (!__real_system_property_get) {
        void *handle = dlopen("libc.so", sdk_int(env) >= 21 ? RTLD_NOLOAD : 0);
        if (!handle)
            log_android(ANDROID_LOG_ERROR, "dlopen(libc.so): %s", dlerror());
        else {
            __real_system_property_get = (PFN_SYS_PROP_GET) dlsym(
                    handle, "__system_property_get");
            if (!__real_system_property_get)
                log_android(ANDROID_LOG_ERROR, "dlsym(__system_property_get()): %s", dlerror());
        }
    }
    return (*__real_system_property_get)(name, value);
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

static jmethodID midLogPacket = NULL;

void log_packet(const struct arguments *args, jobject jpacket) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);

    const char *signature = "(Leu/faircode/netguard/Packet;)V";
    if (midLogPacket == NULL)
        midLogPacket = jniGetMethodID(args->env, clsService, "logPacket", signature);

    (*args->env)->CallVoidMethod(args->env, args->instance, midLogPacket, jpacket);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jpacket);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_packet %f", mselapsed);
#endif
}

static jmethodID midDnsResolved = NULL;
static jmethodID midInitRR = NULL;
jfieldID fidQTime = NULL;
jfieldID fidQName = NULL;
jfieldID fidAName = NULL;
jfieldID fidResource = NULL;
jfieldID fidTTL = NULL;

void dns_resolved(const struct arguments *args,
                  const char *qname, const char *aname, const char *resource, int ttl) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);

    const char *signature = "(Leu/faircode/netguard/ResourceRecord;)V";
    if (midDnsResolved == NULL)
        midDnsResolved = jniGetMethodID(args->env, clsService, "dnsResolved", signature);

    const char *rr = "eu/faircode/netguard/ResourceRecord";
    if (midInitRR == NULL)
        midInitRR = jniGetMethodID(args->env, clsRR, "<init>", "()V");

    jobject jrr = jniNewObject(args->env, clsRR, midInitRR, rr);

    if (fidQTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidQTime = jniGetFieldID(args->env, clsRR, "Time", "J");
        fidQName = jniGetFieldID(args->env, clsRR, "QName", string);
        fidAName = jniGetFieldID(args->env, clsRR, "AName", string);
        fidResource = jniGetFieldID(args->env, clsRR, "Resource", string);
        fidTTL = jniGetFieldID(args->env, clsRR, "TTL", "I");
    }

    jlong jtime = time(NULL) * 1000LL;
    jstring jqname = (*args->env)->NewStringUTF(args->env, qname);
    jstring janame = (*args->env)->NewStringUTF(args->env, aname);
    jstring jresource = (*args->env)->NewStringUTF(args->env, resource);

    (*args->env)->SetLongField(args->env, jrr, fidQTime, jtime);
    (*args->env)->SetObjectField(args->env, jrr, fidQName, jqname);
    (*args->env)->SetObjectField(args->env, jrr, fidAName, janame);
    (*args->env)->SetObjectField(args->env, jrr, fidResource, jresource);
    (*args->env)->SetIntField(args->env, jrr, fidTTL, ttl);

    (*args->env)->CallVoidMethod(args->env, args->instance, midDnsResolved, jrr);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jresource);
    (*args->env)->DeleteLocalRef(args->env, janame);
    (*args->env)->DeleteLocalRef(args->env, jqname);
    (*args->env)->DeleteLocalRef(args->env, jrr);
    (*args->env)->DeleteLocalRef(args->env, clsService);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_packet %f", mselapsed);
#endif
}

static jmethodID midIsDomainBlocked = NULL;

jboolean is_domain_blocked(const struct arguments *args, const char *name) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);

    const char *signature = "(Ljava/lang/String;)Z";
    if (midIsDomainBlocked == NULL)
        midIsDomainBlocked = jniGetMethodID(args->env, clsService, "isDomainBlocked", signature);

    jstring jname = (*args->env)->NewStringUTF(args->env, name);

    jboolean jallowed = (*args->env)->CallBooleanMethod(
            args->env, args->instance, midIsDomainBlocked, jname);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jname);
    (*args->env)->DeleteLocalRef(args->env, clsService);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "is_domain_blocked %f", mselapsed);
#endif

    return jallowed;
}

static jmethodID midIsAddressAllowed = NULL;
jfieldID fidRaddr = NULL;
jfieldID fidRport = NULL;
struct allowed allowed;

struct allowed *is_address_allowed(const struct arguments *args, jobject jpacket) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);

    const char *signature = "(Leu/faircode/netguard/Packet;)Leu/faircode/netguard/Allowed;";
    if (midIsAddressAllowed == NULL)
        midIsAddressAllowed = jniGetMethodID(args->env, clsService, "isAddressAllowed", signature);

    jobject jallowed = (*args->env)->CallObjectMethod(
            args->env, args->instance, midIsAddressAllowed, jpacket);
    jniCheckException(args->env);

    if (jallowed != NULL) {
        if (fidRaddr == NULL) {
            const char *string = "Ljava/lang/String;";
            fidRaddr = jniGetFieldID(args->env, clsAllowed, "raddr", string);
            fidRport = jniGetFieldID(args->env, clsAllowed, "rport", "I");
        }

        jstring jraddr = (*args->env)->GetObjectField(args->env, jallowed, fidRaddr);
        if (jraddr == NULL)
            *allowed.raddr = 0;
        else {
            const char *raddr = (*args->env)->GetStringUTFChars(args->env, jraddr, NULL);
            strcpy(allowed.raddr, raddr);
            (*args->env)->ReleaseStringUTFChars(args->env, jraddr, raddr);
        }
        allowed.rport = (uint16_t) (*args->env)->GetIntField(args->env, jallowed, fidRport);

        (*args->env)->DeleteLocalRef(args->env, jraddr);
    }


    (*args->env)->DeleteLocalRef(args->env, jpacket);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jallowed);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "is_address_allowed %f", mselapsed);
#endif

    return (jallowed == NULL ? NULL : &allowed);
}

jmethodID midInitPacket = NULL;

jfieldID fidTime = NULL;
jfieldID fidVersion = NULL;
jfieldID fidProtocol = NULL;
jfieldID fidFlags = NULL;
jfieldID fidSaddr = NULL;
jfieldID fidSport = NULL;
jfieldID fidDaddr = NULL;
jfieldID fidDport = NULL;
jfieldID fidData = NULL;
jfieldID fidUid = NULL;
jfieldID fidAllowed = NULL;

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
                      jboolean allowed) {
    JNIEnv *env = args->env;

#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    /*
        jbyte b[] = {1,2,3};
        jbyteArray ret = env->NewByteArray(3);
        env->SetByteArrayRegion (ret, 0, 3, b);
     */

    const char *packet = "eu/faircode/netguard/Packet";
    if (midInitPacket == NULL)
        midInitPacket = jniGetMethodID(env, clsPacket, "<init>", "()V");
    jobject jpacket = jniNewObject(env, clsPacket, midInitPacket, packet);

    if (fidTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidTime = jniGetFieldID(env, clsPacket, "time", "J");
        fidVersion = jniGetFieldID(env, clsPacket, "version", "I");
        fidProtocol = jniGetFieldID(env, clsPacket, "protocol", "I");
        fidFlags = jniGetFieldID(env, clsPacket, "flags", string);
        fidSaddr = jniGetFieldID(env, clsPacket, "saddr", string);
        fidSport = jniGetFieldID(env, clsPacket, "sport", "I");
        fidDaddr = jniGetFieldID(env, clsPacket, "daddr", string);
        fidDport = jniGetFieldID(env, clsPacket, "dport", "I");
        fidData = jniGetFieldID(env, clsPacket, "data", string);
        fidUid = jniGetFieldID(env, clsPacket, "uid", "I");
        fidAllowed = jniGetFieldID(env, clsPacket, "allowed", "Z");
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    jlong t = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    jstring jflags = (*env)->NewStringUTF(env, flags);
    jstring jsource = (*env)->NewStringUTF(env, source);
    jstring jdest = (*env)->NewStringUTF(env, dest);
    jstring jdata = (*env)->NewStringUTF(env, data);

    (*env)->SetLongField(env, jpacket, fidTime, t);
    (*env)->SetIntField(env, jpacket, fidVersion, version);
    (*env)->SetIntField(env, jpacket, fidProtocol, protocol);
    (*env)->SetObjectField(env, jpacket, fidFlags, jflags);
    (*env)->SetObjectField(env, jpacket, fidSaddr, jsource);
    (*env)->SetIntField(env, jpacket, fidSport, sport);
    (*env)->SetObjectField(env, jpacket, fidDaddr, jdest);
    (*env)->SetIntField(env, jpacket, fidDport, dport);
    (*env)->SetObjectField(env, jpacket, fidData, jdata);
    (*env)->SetIntField(env, jpacket, fidUid, uid);
    (*env)->SetBooleanField(env, jpacket, fidAllowed, allowed);

    (*env)->DeleteLocalRef(env, jdata);
    (*env)->DeleteLocalRef(env, jdest);
    (*env)->DeleteLocalRef(env, jsource);
    (*env)->DeleteLocalRef(env, jflags);
    // Caller needs to delete reference to packet

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "create_packet %f", mselapsed);
#endif

    return jpacket;
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
    if (fwrite(ptr, len, 1, pcap_file) < 1)
        log_android(ANDROID_LOG_ERROR, "PCAP fwrite error %d: %s", errno, strerror(errno));
    else {
        long fsize = ftell(pcap_file);
        log_android(ANDROID_LOG_VERBOSE, "PCAP wrote %d @%ld", len, fsize);

        if (fsize > MAX_PCAP_FILE) {
            log_android(ANDROID_LOG_WARN, "PCAP truncate @%ld", fsize);
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
}

int compare_u16(uint32_t s1, uint32_t s2) {
    // https://tools.ietf.org/html/rfc1982
    if (s1 == s2)
        return 0;

    int i1 = s1;
    int i2 = s2;
    if ((i1 < i2 && i2 - i1 < 0x7FFFFFFF) ||
        (i1 > i2 && i1 - i2 > 0x7FFFFFFF))
        return -1;
    else
        return 1;
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
        case TCP_CLOSING:
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
