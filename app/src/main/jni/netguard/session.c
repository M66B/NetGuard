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
extern int pipefds[2];
extern pthread_t thread_id;
extern pthread_mutex_t lock;

struct ng_session *ng_session = NULL;

void init(const struct arguments *args) {
    ng_session = NULL;
}

void clear() {
    struct ng_session *s = ng_session;
    while (s != NULL) {
        if (s->socket >= 0 && close(s->socket))
            log_android(ANDROID_LOG_ERROR, "close %d error %d: %s",
                        s->socket, errno, strerror(errno));
        if (s->protocol == IPPROTO_TCP)
            clear_tcp_data(&s->tcp);
        struct ng_session *p = s;
        s = s->next;
        free(p);
    }
    ng_session = NULL;
}

void *handle_events(void *a) {
    int epoll_fd;
    struct timespec ts;

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

    // Get max sessions
    int maxsessions = 1024;
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim))
        log_android(ANDROID_LOG_WARN, "getrlimit error %d: %s", errno, strerror(errno));
    else {
        maxsessions = (int) (rlim.rlim_cur * 75 / 100);
        log_android(ANDROID_LOG_WARN, "getrlimit soft %d hard %d max sessions %d",
                    rlim.rlim_cur, rlim.rlim_max, maxsessions);
    }

    // Terminate existing sessions not allowed anymore
    check_allowed(args);

    int stopping = 0;

    // Open epoll fd
    epoll_fd = epoll_create(1);
    if (epoll_fd < 0) {
        log_android(ANDROID_LOG_ERROR, "epoll create error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll create error %d: %s", errno, strerror(errno));
        stopping = 1;
    }

    // Monitor stop events
    struct epoll_event ev_pipe;
    memset(&ev_pipe, 0, sizeof(struct epoll_event));
    ev_pipe.events = EPOLLIN;
    ev_pipe.data.ptr = &ev_pipe;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipefds[0], &ev_pipe)) {
        log_android(ANDROID_LOG_ERROR, "epoll add pipe error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll add pipe error %d: %s", errno, strerror(errno));
        stopping = 1;
    }

    // Monitor tun events
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = NULL;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->tun, &ev_tun)) {
        log_android(ANDROID_LOG_ERROR, "epoll add tun error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll add tun error %d: %s", errno, strerror(errno));
        stopping = 1;
    }

    // Loop
    while (!stopping) {
        log_android(ANDROID_LOG_DEBUG, "Loop thread %x", thread_id);

        // Count sessions
        int isessions = 0;
        int usessions = 0;
        int tsessions = 0;
        struct ng_session *s = ng_session;
        while (s != NULL) {
            int del = 0;
            if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                if (!s->icmp.stop)
                    isessions++;
            }
            else if (s->protocol == IPPROTO_UDP) {
                if (s->udp.state == UDP_ACTIVE)
                    usessions++;
            }
            else if (s->protocol == IPPROTO_TCP) {
                if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE)
                    tsessions++;
            }
            s = s->next;
        }
        int sessions = isessions + usessions + tsessions;

        // Check sessions
        struct ng_session *sl = NULL;
        s = ng_session;
        while (s != NULL) {
            int del = 0;
            if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6)
                del = check_icmp_session(args, s, sessions, maxsessions);
            else if (s->protocol == IPPROTO_UDP)
                del = check_udp_session(args, s, sessions, maxsessions);
            else if (s->protocol == IPPROTO_TCP)
                del = check_tcp_session(args, s, sessions, maxsessions);

            if (del) {
                if (sl == NULL)
                    ng_session = s->next;
                else
                    sl->next = s->next;

                struct ng_session *c = s;
                s = s->next;
                if (c->protocol == IPPROTO_TCP)
                    clear_tcp_data(&c->tcp);
                free(c);
            } else {
                sl = s;
                s = s->next;
            }
        }

        log_android(ANDROID_LOG_DEBUG, "sessions ICMP %d UDP %d TCP %d max %d/%d",
                    isessions, usessions, tsessions, sessions, maxsessions);

        // Next event time
        ts.tv_sec = get_select_timeout(sessions, maxsessions);
        ts.tv_nsec = 0;

        // TODO: check if tun is writable?

        // Poll
        struct epoll_event ev;
        int ready = epoll_wait(epoll_fd, &ev, 1, ts.tv_sec * 1000);

        if (ready < 0) {
            if (errno == EINTR) {
                log_android(ANDROID_LOG_DEBUG,
                            "epoll interrupted tun %d thread %x", args->tun, thread_id);
                continue;
            } else {
                log_android(ANDROID_LOG_ERROR,
                            "epoll tun %d thread %x error %d: %s",
                            args->tun, thread_id, errno, strerror(errno));
                report_exit(args, "epoll tun %d thread %x error %d: %s",
                            args->tun, thread_id, errno, strerror(errno));
                break;
            }
        }

        if (ready == 0)
            log_android(ANDROID_LOG_DEBUG, "epoll timeout");
        else {
            if (ev.data.ptr != &ev_pipe) {
                if (ev.data.ptr == NULL)
                    log_android(ANDROID_LOG_DEBUG, "epoll ready %d in %d out %d err %d",
                                ready,
                                (ev.events & EPOLLIN) != 0,
                                (ev.events & EPOLLOUT) != 0,
                                (ev.events & EPOLLERR) != 0);
                else
                    log_android(ANDROID_LOG_DEBUG,
                                "epoll ready %d in %d out %d err %d prot %d sock %d",
                                ready,
                                (ev.events & EPOLLIN) != 0,
                                (ev.events & EPOLLOUT) != 0,
                                (ev.events & EPOLLERR) != 0,
                                ((struct ng_session *) ev.data.ptr)->protocol,
                                ((struct ng_session *) ev.data.ptr)->socket);
            }

            if (pthread_mutex_lock(&lock))
                log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

#ifdef PROFILE_EVENTS
            struct timeval start, end;
            float mselapsed;
            gettimeofday(&start, NULL);
#endif

            // Check upstream
            int error = 0;
            if (ev.data.ptr == &ev_pipe) {
                stopping = 1;
                uint8_t buffer[1];
                if (read(pipefds[0], buffer, 1) < 0)
                    log_android(ANDROID_LOG_WARN, "Read pipe error %d: %s", errno, strerror(errno));
                else
                    log_android(ANDROID_LOG_WARN, "Read pipe");

            } else if (ev.data.ptr == NULL) {
                if (check_tun(args, &ev, epoll_fd, sessions, maxsessions) < 0)
                    error = 1;

            } else {
#ifdef PROFILE_EVENTS
                gettimeofday(&end, NULL);
                mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                            (end.tv_usec - start.tv_usec) / 1000.0;
                if (mselapsed > PROFILE_EVENTS)
                    log_android(ANDROID_LOG_WARN, "tun %f", mselapsed);

                gettimeofday(&start, NULL);
#endif

                // Check downstream
                struct ng_session *session = (struct ng_session *) ev.data.ptr;
                if (session->protocol == IPPROTO_ICMP || session->protocol == IPPROTO_ICMPV6)
                    check_icmp_socket(args, &ev);
                else if (session->protocol == IPPROTO_UDP)
                    check_udp_socket(args, &ev);
                else if (session->protocol == IPPROTO_TCP)
                    check_tcp_socket(args, &ev, epoll_fd);
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

    // Close epoll fd
    if (epoll_fd >= 0 && close(epoll_fd))
        log_android(ANDROID_LOG_ERROR,
                    "epoll close error %d: %s", errno, strerror(errno));

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

    struct ng_session *s = ng_session;
    while (s != NULL) {
        if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
            if (!s->icmp.stop) {
                int stimeout =
                        s->icmp.time + get_icmp_timeout(&s->icmp, sessions, maxsessions) - now + 1;
                if (stimeout > 0 && stimeout < timeout)
                    timeout = stimeout;
            }

        } else if (s->protocol == IPPROTO_UDP) {
            if (s->udp.state == UDP_ACTIVE) {
                int stimeout =
                        s->udp.time + get_udp_timeout(&s->udp, sessions, maxsessions) - now + 1;
                if (stimeout > 0 && stimeout < timeout)
                    timeout = stimeout;
            }

        } else if (s->protocol == IPPROTO_TCP) {
            if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE) {
                int stimeout =
                        s->tcp.time + get_tcp_timeout(&s->tcp, sessions, maxsessions) - now + 1;
                if (stimeout > 0 && stimeout < timeout)
                    timeout = stimeout;
            }

        }

        s = s->next;
    }

    return timeout;
}

void check_allowed(const struct arguments *args) {
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    struct ng_session *l = NULL;
    struct ng_session *s = ng_session;
    while (s != NULL) {
        if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
            if (!s->icmp.stop) {
                if (s->icmp.version == 4) {
                    inet_ntop(AF_INET, &s->icmp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->icmp.daddr.ip4, dest, sizeof(dest));
                }
                else {
                    inet_ntop(AF_INET6, &s->icmp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->icmp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->icmp.version, IPPROTO_ICMP, "",
                        source, 0, dest, 0, "", s->icmp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    s->icmp.stop = 1;
                    log_android(ANDROID_LOG_WARN, "ICMP terminate %d uid %d",
                                s->socket, s->icmp.uid);
                }
            }

        } else if (s->protocol == IPPROTO_UDP) {
            if (s->udp.state == UDP_ACTIVE) {
                if (s->udp.version == 4) {
                    inet_ntop(AF_INET, &s->udp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->udp.daddr.ip4, dest, sizeof(dest));
                }
                else {
                    inet_ntop(AF_INET6, &s->udp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->udp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->udp.version, IPPROTO_UDP, "",
                        source, ntohs(s->udp.source), dest, ntohs(s->udp.dest), "", s->udp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    s->udp.state = UDP_FINISHING;
                    log_android(ANDROID_LOG_WARN, "UDP terminate session socket %d uid %d",
                                s->socket, s->udp.uid);
                }
            }
            else if (s->udp.state == UDP_BLOCKED) {
                log_android(ANDROID_LOG_WARN, "UDP remove blocked session uid %d", s->udp.uid);

                if (l == NULL)
                    ng_session = s->next;
                else
                    l->next = s->next;

                struct ng_session *c = s;
                s = s->next;
                free(c);
                continue;
            }

        } else if (s->protocol == IPPROTO_TCP) {
            if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE) {
                if (s->tcp.version == 4) {
                    inet_ntop(AF_INET, &s->tcp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->tcp.daddr.ip4, dest, sizeof(dest));
                }
                else {
                    inet_ntop(AF_INET6, &s->tcp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->tcp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->tcp.version, IPPROTO_TCP, "",
                        source, ntohs(s->tcp.source), dest, ntohs(s->tcp.dest), "", s->tcp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    write_rst(args, &s->tcp);
                    log_android(ANDROID_LOG_WARN, "TCP terminate socket %d uid %d",
                                s->socket, s->tcp.uid);
                }
            }

        }

        l = s;
        s = s->next;
    }
}

