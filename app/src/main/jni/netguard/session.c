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

extern JavaVM *jvm;
extern pthread_t thread_id;
extern pthread_mutex_t lock;
extern jboolean stopping;
extern jboolean signaled;

struct icmp_session *icmp_session = NULL;
struct udp_session *udp_session = NULL;
struct tcp_session *tcp_session = NULL;

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
