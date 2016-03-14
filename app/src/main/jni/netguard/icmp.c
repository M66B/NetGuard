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

struct icmp_session *icmp_session = NULL;
extern FILE *pcap_file;

void init_icmp(const struct arguments *args) {
    icmp_session = NULL;
}

void clear_icmp() {
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
}

int get_icmp_sessions() {
    int count = 0;
    struct icmp_session *ic = icmp_session;
    while (ic != NULL) {
        if (!ic->stop)
            count++;
        ic = ic->next;
    }
    return count;
}

int get_icmp_timeout(const struct icmp_session *u, int sessions, int maxsessions) {
    int timeout = ICMP_TIMEOUT;

    int scale = 100 - sessions * 100 / maxsessions;
    timeout = timeout * scale / 100;

    return timeout;
}

void check_icmp_sessions(const struct arguments *args, int sessions, int maxsessions) {
    time_t now = time(NULL);

    struct icmp_session *il = NULL;
    struct icmp_session *i = icmp_session;
    while (i != NULL) {
        int timeout = get_icmp_timeout(i, sessions, maxsessions);
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
        log_android(ANDROID_LOG_ERROR, "write %d/%d", res, len);
        return -1;
    }

    return res;
}
