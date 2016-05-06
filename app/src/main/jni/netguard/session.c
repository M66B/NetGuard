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

#include "netguard.h"

int ebadf = 0;

extern JavaVM *jvm;
extern pthread_t thread_id;
extern pthread_mutex_t lock;
extern jboolean stopping;
extern jboolean signaled;

extern struct icmp_session *icmp_session;
extern struct udp_session *udp_session;
extern struct tcp_session *tcp_session;

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

    int maxsessions = 1024;
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim))
        log_android(ANDROID_LOG_WARN, "getrlimit error %d: %s", errno, strerror(errno));
    else {
        maxsessions = (int) (rlim.rlim_cur * 50 / 100);
        log_android(ANDROID_LOG_WARN, "getrlimit soft %d hard %d max sessions %d",
                    rlim.rlim_cur, rlim.rlim_max, maxsessions);
    }
    if (maxsessions > FD_SETSIZE)
        maxsessions = FD_SETSIZE;

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
    ebadf = 0;

    // Loop
    while (!stopping) {
        log_android(ANDROID_LOG_DEBUG, "Loop thread %x", thread_id);

        // Count sessions
        int isessions = get_icmp_sessions();
        int usessions = get_udp_sessions();
        int tsessions = get_tcp_sessions();
        int sessions = isessions + usessions + tsessions;

        // Check sessions
        check_icmp_sessions(args, sessions, maxsessions);
        check_udp_sessions(args, sessions, maxsessions);
        check_tcp_sessions(args, sessions, maxsessions);

        // https://bugzilla.mozilla.org/show_bug.cgi?id=1093893
        int idle = (tsessions + usessions + tsessions == 0 && sdk >= 16);
        log_android(ANDROID_LOG_DEBUG, "sessions ICMP %d UDP %d TCP %d max %d/%d idle %d sdk %d",
                    isessions, usessions, tsessions, sessions, maxsessions, idle, sdk);

        // Next event time
        ts.tv_sec = (sdk < 16 ? 5 : get_select_timeout(sessions, maxsessions));
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
                    log_android(ANDROID_LOG_DEBUG,
                                "pselect interrupted tun %d thread %x", args->tun, thread_id);
                    continue;
                }
            } else if (errno == EBADF) {
                struct stat sb;
                if (fstat(args->tun, &sb) < 0) {
                    log_android(ANDROID_LOG_ERROR,
                                "tun socket %d select error %d: %s",
                                args->tun, errno, strerror(errno));
                    report_exit(args, "tun socket %d select error %d: %s",
                                args->tun, errno, strerror(errno));
                    break;
                }
                else {
                    if (ebadf++ < 10) {
                        log_android(ANDROID_LOG_WARN, "pselect EBADF, try %d", ebadf);
                        continue;
                    } else {
                        report_exit(args, "pselect error %d: %s", errno, strerror(errno));
                        break;
                    }
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
            if (check_tun(args, &rfds, &wfds, &efds, sessions, maxsessions) < 0)
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

int get_select_timeout(int sessions, int maxsessions) {
    time_t now = time(NULL);
    int timeout = SELECT_TIMEOUT;

    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        if (!i->stop) {
            int stimeout = i->time + get_icmp_timeout(i, sessions, maxsessions) - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        i = i->next;
    }

    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->state == UDP_ACTIVE) {
            int stimeout = u->time + get_udp_timeout(u, sessions, maxsessions) - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        u = u->next;
    }

    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->state != TCP_CLOSING && t->state != TCP_CLOSE) {
            int stimeout = t->time + get_tcp_timeout(t, sessions, maxsessions) - now + 1;
            if (stimeout > 0 && stimeout < timeout)
                timeout = stimeout;
        }
        t = t->next;
    }

    return timeout;
}

int get_selects(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct stat sb;

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
            if (fstat(i->socket, &sb) < 0) {
                log_android(ANDROID_LOG_WARN, "ICMP socket %d select error %d: %s",
                            i->socket, errno, strerror(errno));
                i->stop = 1;
            } else {
                FD_SET(i->socket, efds);
                FD_SET(i->socket, rfds);
                if (i->socket > max)
                    max = i->socket;
            }
        }
        i = i->next;
    }

    // Select UDP sockets
    struct udp_session *u = udp_session;
    while (u != NULL) {
        if (u->state == UDP_ACTIVE) {
            if (fstat(u->socket, &sb) < 0) {
                log_android(ANDROID_LOG_WARN, "UDP socket %d select error %d: %s",
                            u->socket, errno, strerror(errno));
                u->state = UDP_FINISHING;
            }
            else {
                FD_SET(u->socket, efds);
                FD_SET(u->socket, rfds);
                if (u->socket > max)
                    max = u->socket;
            }
        }
        u = u->next;
    }

    // Select TCP sockets
    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        // Select sockets
        if (t->socket >= 0) {
            if (fstat(t->socket, &sb) < 0) {
                log_android(ANDROID_LOG_WARN, "TCP socket %d select error %d: %s",
                            t->socket, errno, strerror(errno));
                write_rst(args, t);
            }
            else {
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
                    if (get_send_window(t) > 0)
                        FD_SET(t->socket, rfds);

                    // Check for outgoing data
                    if (t->forward != NULL)
                        FD_SET(t->socket, wfds);

                    if (t->socket > max)
                        max = t->socket;
                }
            }
        }

        t = t->next;
    }

    return max;
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

