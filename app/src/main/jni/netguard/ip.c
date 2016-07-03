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

int max_tun_msg = 0;
extern int loglevel;
extern FILE *pcap_file;

uint16_t get_mtu() {
    return 10000;
}

uint16_t get_default_mss(int version) {
    if (version == 4)
        return (uint16_t) (get_mtu() - sizeof(struct iphdr) - sizeof(struct tcphdr));
    else
        return (uint16_t) (get_mtu() - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));
}

int check_tun(const struct arguments *args,
              const struct epoll_event *ev,
              const int epoll_fd,
              int sessions, int maxsessions) {
    // Check tun error
    if (ev->events & EPOLLERR) {
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
    if (ev->events & EPOLLIN) {
        uint8_t *buffer = malloc(get_mtu());
        ssize_t length = read(args->tun, buffer, get_mtu());
        if (length < 0) {
            free(buffer);

            log_android(ANDROID_LOG_ERROR, "tun %d read error %d: %s",
                        args->tun, errno, strerror(errno));
            if (errno == EINTR || errno == EAGAIN)
                // Retry later
                return 0;
            else {
                report_exit(args, "tun %d read error %d: %s",
                            args->tun, errno, strerror(errno));
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
            handle_ip(args, buffer, (size_t) length, epoll_fd, sessions, maxsessions);

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

void handle_ip(const struct arguments *args,
               const uint8_t *pkt, const size_t length,
               const int epoll_fd,
               int sessions, int maxsessions) {
    uint8_t protocol;
    void *saddr;
    void *daddr;
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];
    char flags[10];
    int flen = 0;
    uint8_t *payload;

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
            log_android(ANDROID_LOG_ERROR, "IP fragment offset %u",
                        (ip4hdr->frag_off & IP_OFFMASK) * 8);
            return;
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

        // TODO checksum
    }
    else {
        log_android(ANDROID_LOG_ERROR, "Unknown version %d", version);
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
    else if (protocol != IPPROTO_HOPOPTS && protocol != IPPROTO_IGMP && protocol != IPPROTO_ESP)
        report_error(args, 1, "Unknown protocol %d", protocol);

    flags[flen] = 0;

    // Limit number of sessions
    if (sessions >= maxsessions) {
        if ((protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) ||
            (protocol == IPPROTO_UDP && !has_udp_session(args, pkt, payload)) ||
            (protocol == IPPROTO_TCP && syn)) {
            log_android(ANDROID_LOG_ERROR,
                        "%d of max %d sessions, dropping version %d protocol %d",
                        sessions, maxsessions, protocol, version);
            return;
        }
    }

    // Get uid
    jint uid = -1;
    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6 ||
        (protocol == IPPROTO_UDP && !has_udp_session(args, pkt, payload)) ||
        (protocol == IPPROTO_TCP && syn))
        uid = get_uid_retry(version, protocol, saddr, sport);

    log_android(ANDROID_LOG_DEBUG,
                "Packet v%d %s/%u > %s/%u proto %d flags %s uid %d",
                version, source, sport, dest, dport, protocol, flags, uid);

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
            handle_icmp(args, pkt, length, payload, uid, epoll_fd);
        else if (protocol == IPPROTO_UDP)
            handle_udp(args, pkt, length, payload, uid, redirect, epoll_fd);
        else if (protocol == IPPROTO_TCP)
            handle_tcp(args, pkt, length, payload, uid, redirect, epoll_fd);
    }
    else {
        if (protocol == IPPROTO_UDP)
            block_udp(args, pkt, length, payload, uid);
        log_android(ANDROID_LOG_WARN, "Address v%d p%d %s/%u syn %d not allowed",
                    version, protocol, dest, dport, syn);
    }
}

jint get_uid_retry(const int version, const int protocol,
                   const void *saddr, const uint16_t sport) {
    char source[INET6_ADDRSTRLEN + 1];
    inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
    log_android(ANDROID_LOG_INFO, "get uid v%d p%d %s/%u", version, protocol, source, sport);

    jint uid = -1;
    int tries = 0;
    usleep(1000 * UID_DELAY);
    while (uid < 0 && tries++ < UID_MAXTRY) {
        // Check IPv6 table first
        if (version == 4) {
            int8_t saddr128[16];
            memset(saddr128, 0, 10);
            saddr128[10] = (uint8_t) 0xFF;
            saddr128[11] = (uint8_t) 0xFF;
            memcpy(saddr128 + 12, saddr, 4);
            uid = get_uid(6, protocol, saddr128, sport, tries == UID_MAXTRY);
        }

        if (uid < 0)
            uid = get_uid(version, protocol, saddr, sport, tries == UID_MAXTRY);

        // Retry delay
        if (uid < 0 && tries < UID_MAXTRY) {
            log_android(ANDROID_LOG_WARN, "get uid v%d p%d %s/%u try %d",
                        version, protocol, source, sport, tries);
            usleep(1000 * UID_DELAYTRY);
        }
    }

    if (uid < 0)
        log_android(ANDROID_LOG_ERROR, "uid v%d p%d %s/%u not found",
                    version, protocol, source, sport);

    return uid;
}

jint get_uid(const int version, const int protocol,
             const void *saddr, const uint16_t sport,
             int dump) {
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

    // NETLINK is not available on Android due to SELinux policies :-(

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
    *line = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (i++) {
            *hex = 0;
            port = -1;
            u = -1;
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
            if (fields == 3 &&
                (version == 4 ? strlen(hex) == 8 : strlen(hex) == 32) && port >= 0 && u >= 0) {
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
