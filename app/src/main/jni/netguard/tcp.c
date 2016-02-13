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

struct tcp_session *tcp_session;
extern FILE *pcap_file;

void init_tcp(const struct arguments *args) {
    tcp_session = NULL;
}

void clear_tcp() {
    struct tcp_session *t = tcp_session;
    while (t != NULL) {
        if (t->socket >= 0 && close(t->socket))
            log_android(ANDROID_LOG_ERROR, "TCP close %d error %d: %s",
                        t->socket, errno, strerror(errno));
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

int get_tcp_sessions() {
    int count = 0;
    struct tcp_session *tc = tcp_session;
    while (tc != NULL) {
        if (tc->state != TCP_CLOSING && tc->state != TCP_CLOSE)
            count++;
        tc = tc->next;
    }
    return count;
}

int get_tcp_timeout(const struct tcp_session *t, int sessions, int maxsessions) {
    int timeout;
    if (t->state == TCP_LISTEN || t->state == TCP_SYN_RECV)
        timeout = TCP_INIT_TIMEOUT;
    else if (t->state == TCP_ESTABLISHED) {
        if (t->keep_alive)
            timeout = TCP_IDLE_TIMEOUT;
        else
            timeout = TCP_IDLE_TIMEOUT / 2;
    } else
        timeout = TCP_CLOSE_TIMEOUT;

    int scale = 100 - sessions * 100 / maxsessions;
    timeout = timeout * scale / 100;

    return timeout;
}

void check_tcp_sessions(const struct arguments *args, int sessions, int maxsessions) {
    time_t now = time(NULL);

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

        int timeout = get_tcp_timeout(t, sessions, maxsessions);

        // Keep alive
        if (t->state == TCP_ESTABLISHED && t->keep_alive == 0 && t->time + timeout < now) {
            log_android(ANDROID_LOG_WARN, "%s keep alive %d/%d sec ",
                        session, now - t->time, timeout);
            t->keep_alive = time(NULL);
            t->local_seq--;
            write_ack(args, t);
            t->local_seq++;

        }
        else {
            // Check session timeout
            if (t->state != TCP_CLOSING && t->state != TCP_CLOSE && t->time + timeout < now) {
                log_android(ANDROID_LOG_WARN, "%s idle %d/%d sec ", session, now - t->time,
                            timeout);
                if (t->state == TCP_LISTEN)
                    t->state = TCP_CLOSING;
                else
                    write_rst(args, t);
            }

            // Check closing sessions
            if (t->state == TCP_CLOSING) {
                // eof closes socket
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

void check_tcp_sockets(const struct arguments *args, fd_set *rfds, fd_set *wfds, fd_set *efds) {
    struct tcp_session *cur = tcp_session;
    while (cur != NULL) {
        if (cur->socket >= 0) {
            int oldstate = cur->state;
            uint32_t oldlocal = cur->local_seq;
            uint32_t oldremote = cur->remote_seq;

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
                        log_android(ANDROID_LOG_INFO, "%s connected", session);

                        cur->remote_seq++; // remote SYN
                        if (write_syn_ack(args, cur) >= 0) {
                            cur->time = time(NULL);
                            cur->local_seq++; // local SYN
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
                    cur->recv_window = (uint16_t) window;
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
                    if (fwd || (prev == 0 && window > 0)) {
                        if (fwd && cur->forward == NULL && cur->state == TCP_CLOSE_WAIT) {
                            log_android(ANDROID_LOG_WARN, "%s confirm FIN", session);
                            cur->remote_seq++; // remote FIN
                        }
                        if (write_ack(args, cur) >= 0)
                            cur->time = time(NULL);
                    }

                    if (cur->state == TCP_ESTABLISHED || cur->state == TCP_CLOSE_WAIT) {
                        // Check socket read
                        // Send window can be changed in the mean time

                        if (FD_ISSET(cur->socket, rfds) && cur->send_window > 0) {
                            cur->time = time(NULL);

                            // TODO take into account ACKed?
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
                                    if (write_fin_ack(args, cur) >= 0) {
                                        log_android(ANDROID_LOG_WARN, "%s FIN sent", session);
                                        cur->local_seq++; // local FIN
                                    }

                                    if (cur->state == TCP_ESTABLISHED)
                                        cur->state = TCP_FIN_WAIT1;
                                    else if (cur->state == TCP_CLOSE_WAIT)
                                        cur->state = TCP_LAST_ACK;
                                    else
                                        log_android(ANDROID_LOG_ERROR, "%s invalid close", session);
                                }
                                else {
                                    // There was still data to send
                                    log_android(ANDROID_LOG_ERROR, "%s close with queue", session);
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
    const uint8_t *tcpoptions = payload + sizeof(struct tcphdr);
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
    if (tcphdr->psh)
        flags[flen++] = 'P';
    if (tcphdr->fin)
        flags[flen++] = 'F';
    if (tcphdr->rst)
        flags[flen++] = 'R';
    if (tcphdr->urg)
        flags[flen++] = 'U';
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
    log_android(tcphdr->urg ? ANDROID_LOG_WARN : ANDROID_LOG_DEBUG, packet);

    // Check session
    if (cur == NULL) {
        if (tcphdr->syn) {
            // Decode options
            // http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
            uint16_t mss = 0;
            int optlen = tcpoptlen;
            uint8_t *options = tcpoptions;
            while (optlen > 0) {
                uint8_t kind = *options;
                uint8_t len = *(options + 1);
                if (kind == 0) // End of options list
                    break;

                if (kind == 2)
                    mss = ntohs(*((uint16_t *) (options + 2)));

                if (kind == 1) {
                    optlen--;
                    options++;
                }
                else {
                    optlen -= len;
                    options += len;
                }
            }

            log_android(ANDROID_LOG_WARN, "%s new session mss %d", packet, mss);

            // Register session
            struct tcp_session *syn = malloc(sizeof(struct tcp_session));
            syn->time = time(NULL);
            syn->keep_alive = 0;
            syn->uid = uid;
            syn->version = version;
            syn->recv_window = TCP_RECV_WINDOW;
            syn->send_window = ntohs(tcphdr->window);
            syn->remote_seq = ntohl(tcphdr->seq); // ISN remote
            syn->local_seq = (uint32_t) rand(); // ISN local
            syn->remote_start = syn->remote_seq;
            syn->local_start = syn->local_seq;
            syn->acked = 0;

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
                "%s %s loc %u rem %u acked %u",
                packet,
                strstate(cur->state),
                cur->local_seq - cur->local_start,
                cur->remote_seq - cur->remote_start,
                cur->acked - cur->local_start);

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

            // Enable socket keep alive
            if (cur->keep_alive) {
                cur->keep_alive = 0;

                if (cur->state == TCP_ESTABLISHED) {
                    int on = 1;
                    if (setsockopt(cur->socket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)))
                        log_android(ANDROID_LOG_ERROR,
                                    "%s setsockopt SO_KEEPALIVE error %d: %s",
                                    session, errno, strerror(errno));
                    else
                        log_android(ANDROID_LOG_WARN, "%s enabled keep alive", session);
                }
            }

            // Do not change the order of the conditions

            // Queue data to forward
            if (datalen) {
                if (cur->socket < 0) {
                    log_android(ANDROID_LOG_ERROR, "%s data while local closed", session);
                    write_rst(args, cur);
                    return 0;
                }
                if (cur->state == TCP_CLOSE_WAIT) {
                    log_android(ANDROID_LOG_ERROR, "%s data while remote closed", session);
                    write_rst(args, cur);
                    return 0;
                }
                queue_tcp(args, tcphdr, session, cur, data, datalen);
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
                            log_android(ANDROID_LOG_WARN, "%s FIN received", session);
                            if (cur->forward == NULL) {
                                cur->remote_seq++; // remote FIN
                                if (write_ack(args, cur) >= 0)
                                    cur->state = TCP_CLOSE_WAIT;
                            }
                            else
                                cur->state = TCP_CLOSE_WAIT;
                        }

                        else if (cur->state == TCP_CLOSE_WAIT) {
                            log_android(ANDROID_LOG_WARN, "%s repeated FIN", session);
                            // The socket is probably not closed yet
                        }

                        else if (cur->state == TCP_FIN_WAIT1) {
                            log_android(ANDROID_LOG_WARN, "%s last ACK", session);
                            cur->remote_seq++; // remote FIN
                            if (write_ack(args, cur) >= 0)
                                cur->state = TCP_CLOSE;
                        }

                        else {
                            log_android(ANDROID_LOG_ERROR, "%s invalid FIN", session);
                            return 0;
                        }

                    } else if (tcphdr->ack) {
                        cur->acked = ntohl(tcphdr->ack_seq);

                        if (cur->state == TCP_SYN_RECV)
                            cur->state = TCP_ESTABLISHED;

                        else if (cur->state == TCP_ESTABLISHED) {
                            // Do nothing
                        }

                        else if (cur->state == TCP_LAST_ACK)
                            cur->state = TCP_CLOSING;

                        else if (cur->state == TCP_CLOSE_WAIT) {
                            // ACK after FIN/ACK
                        }

                        else if (cur->state == TCP_FIN_WAIT1) {
                            // Do nothing
                        }

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
                    uint32_t ack = ntohl(tcphdr->ack_seq);
                    if ((uint32_t) (ack + 1) == cur->local_seq) {
                        // Keep alive
                        if (cur->state == TCP_ESTABLISHED) {
                            int on = 1;
                            if (setsockopt(cur->socket, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)))
                                log_android(ANDROID_LOG_ERROR,
                                            "%s setsockopt SO_KEEPALIVE error %d: %s",
                                            session, errno, strerror(errno));
                            else
                                log_android(ANDROID_LOG_WARN, "%s enabled keep alive", session);
                        }
                        else
                            log_android(ANDROID_LOG_WARN, "%s keep alive", session);

                    } else if (compare_u16(ack, cur->local_seq) < 0) {
                        if (compare_u16(ack, cur->acked) <= 0)
                            log_android(ack == cur->acked ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
                                        "%s repeated ACK %u/%u",
                                        session,
                                        ack - cur->local_start, cur->acked - cur->local_start);
                        else {
                            log_android(ANDROID_LOG_WARN, "%s previous ACK %d",
                                        session, ack - cur->local_seq);
                            cur->acked = ack;
                        }

                        // TODO terminate connection if difference too large
                        return 1;
                    }
                    else {
                        log_android(ANDROID_LOG_ERROR, "%s future ACK", session);
                        write_rst(args, cur);
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

void queue_tcp(const struct arguments *args,
               const struct tcphdr *tcphdr,
               const char *session, struct tcp_session *cur,
               const uint8_t *data, uint16_t datalen) {
    uint32_t seq = ntohl(tcphdr->seq);
    if (compare_u16(seq, cur->remote_seq) < 0)
        log_android(ANDROID_LOG_WARN, "%s already forwarded %u..%u",
                    session,
                    seq - cur->remote_start, seq + datalen - cur->remote_start);
    else {
        struct segment *p = NULL;
        struct segment *s = cur->forward;
        while (s != NULL && compare_u16(s->seq, seq) < 0) {
            p = s;
            s = s->next;
        }

        if (s == NULL || compare_u16(s->seq, seq) > 0) {
            log_android(ANDROID_LOG_DEBUG, "%s queuing %u...%u",
                        session,
                        seq - cur->remote_start, seq + datalen - cur->remote_start);
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
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start);
            else if (s->len < datalen) {
                log_android(ANDROID_LOG_WARN, "%s segment smaller %u..%u > %u",
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start,
                            s->seq + datalen - cur->remote_start);
                free(s->data);
                s->data = malloc(datalen);
                memcpy(s->data, data, datalen);
            }
            else
                log_android(ANDROID_LOG_ERROR, "%s segment larger %u..%u < %u",
                            session,
                            s->seq - cur->remote_start, s->seq + s->len - cur->remote_start,
                            s->seq + datalen - cur->remote_start);
        }
    }
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

int write_syn_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 1, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_data(const struct arguments *args, struct tcp_session *cur,
               const uint8_t *buffer, size_t length) {
    if (write_tcp(args, cur, buffer, length, 0, 1, 0, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

int write_fin_ack(const struct arguments *args, struct tcp_session *cur) {
    if (write_tcp(args, cur, NULL, 0, 0, 1, 1, 0) < 0) {
        cur->state = TCP_CLOSING;
        return -1;
    }
    return 0;
}

void write_rst(const struct arguments *args, struct tcp_session *cur) {
    write_tcp(args, cur, NULL, 0, 0, 0, 0, 1);
    if (cur->state != TCP_CLOSE)
        cur->state = TCP_CLOSING;
}

ssize_t write_tcp(const struct arguments *args, const struct tcp_session *cur,
                  const uint8_t *data, size_t datalen,
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
    tcp->ack_seq = htonl((uint32_t) (cur->remote_seq));
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
                "TCP sending%s%s%s%s to tun %s/%u seq %u ack %u data %u",
                (tcp->syn ? " SYN" : ""),
                (tcp->ack ? " ACK" : ""),
                (tcp->fin ? " FIN" : ""),
                (tcp->rst ? " RST" : ""),
                dest, ntohs(tcp->dest),
                ntohl(tcp->seq) - cur->local_start,
                ntohl(tcp->ack_seq) - cur->remote_start,
                datalen);

    ssize_t res = write(args->tun, buffer, len);

    // Write pcap record
    if (res >= 0) {
        if (pcap_file != NULL)
            write_pcap_rec(buffer, (size_t) res);
    } else
        log_android(ANDROID_LOG_ERROR, "TCP write%s%s%s%s data %d error %d: %s",
                    (tcp->syn ? " SYN" : ""),
                    (tcp->ack ? " ACK" : ""),
                    (tcp->fin ? " FIN" : ""),
                    (tcp->rst ? " RST" : ""),
                    datalen,
                    errno, strerror((errno)));

    free(buffer);

    if (res != len) {
        log_android(ANDROID_LOG_ERROR, "TCP write %d wrote %d", res, len);
        return -1;
    }

    return res;
}
