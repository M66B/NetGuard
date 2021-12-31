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

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

#include "netguard.h"

int32_t get_qname(const uint8_t *data, const size_t datalen, uint16_t off, char *qname) {
    *qname = 0;

    if (off >= datalen)
        return -1;

    uint16_t c = 0;
    uint8_t noff = 0;
    uint16_t ptr = off;
    uint8_t len = *(data + ptr);
    uint8_t count = 0;
    while (len) {
        if (count++ > 25)
            break;

        if (ptr + 1 < datalen && (len & 0xC0)) {
            uint16_t jump = (uint16_t) ((len & 0x3F) * 256 + *(data + ptr + 1));
            if (jump >= datalen) {
                log_android(ANDROID_LOG_DEBUG, "DNS invalid jump");
                break;
            }
            ptr = jump;
            len = *(data + ptr);
            log_android(ANDROID_LOG_DEBUG, "DNS qname compression ptr %d len %d", ptr, len);
            if (!c) {
                c = 1;
                off += 2;
            }
        } else if (ptr + 1 + len < datalen && noff + len <= DNS_QNAME_MAX) {
            memcpy(qname + noff, data + ptr + 1, len);
            *(qname + noff + len) = '.';
            noff += (len + 1);

            uint16_t jump = (uint16_t) (ptr + 1 + len);
            if (jump >= datalen) {
                log_android(ANDROID_LOG_DEBUG, "DNS invalid jump");
                break;
            }
            ptr = jump;
            len = *(data + ptr);
        } else
            break;
    }
    ptr++;

    if (len > 0 || noff == 0) {
        log_android(ANDROID_LOG_ERROR, "DNS qname invalid len %d noff %d", len, noff);
        return -1;
    }

    *(qname + noff - 1) = 0;
    log_android(ANDROID_LOG_DEBUG, "qname %s", qname);

    return (c ? off : ptr);
}

void parse_dns_response(const struct arguments *args, const struct ng_session *s,
                        const uint8_t *data, size_t *datalen) {
    if (*datalen < sizeof(struct dns_header) + 1) {
        log_android(ANDROID_LOG_WARN, "DNS response length %d", *datalen);
        return;
    }

    // Check if standard DNS query
    // TODO multiple qnames
    struct dns_header *dns = (struct dns_header *) data;
    int qcount = ntohs(dns->q_count);
    int acount = ntohs(dns->ans_count);
    if (dns->qr == 1 && dns->opcode == 0 && qcount > 0 && acount > 0) {
        log_android(ANDROID_LOG_DEBUG, "DNS response qcount %d acount %d", qcount, acount);
        if (qcount > 1)
            log_android(ANDROID_LOG_WARN, "DNS response qcount %d acount %d", qcount, acount);

        // http://tools.ietf.org/html/rfc1035
        char name[DNS_QNAME_MAX + 1];
        int32_t off = sizeof(struct dns_header);

        uint16_t qtype;
        uint16_t qclass;
        char qname[DNS_QNAME_MAX + 1];

        for (int q = 0; q < 1; q++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 4 <= *datalen) {
                // TODO multiple qnames?
                if (q == 0) {
                    strcpy(qname, name);
                    qtype = ntohs(*((uint16_t *) (data + off)));
                    qclass = ntohs(*((uint16_t *) (data + off + 2)));
                    log_android(ANDROID_LOG_DEBUG,
                                "DNS question %d qtype %d qclass %d qname %s",
                                q, qtype, qclass, qname);
                }
                off += 4;
            } else {
                log_android(ANDROID_LOG_WARN,
                            "DNS response Q invalid off %d datalen %d", off, *datalen);
                return;
            }
        }

        short svcb = 0;
        int32_t aoff = off;
        for (int a = 0; a < acount; a++) {
            off = get_qname(data, *datalen, (uint16_t) off, name);
            if (off > 0 && off + 10 <= *datalen) {
                uint16_t qtype = ntohs(*((uint16_t *) (data + off)));
                uint16_t qclass = ntohs(*((uint16_t *) (data + off + 2)));
                uint32_t ttl = ntohl(*((uint32_t *) (data + off + 4)));
                uint16_t rdlength = ntohs(*((uint16_t *) (data + off + 8)));
                off += 10;

                if (off + rdlength <= *datalen) {
                    if (qclass == DNS_QCLASS_IN &&
                        (qtype == DNS_QTYPE_A || qtype == DNS_QTYPE_AAAA)) {

                        char rd[INET6_ADDRSTRLEN + 1];
                        if (qtype == DNS_QTYPE_A) {
                            if (off + sizeof(__be32) <= *datalen)
                                inet_ntop(AF_INET, data + off, rd, sizeof(rd));
                            else
                                return;
                        } else if (qclass == DNS_QCLASS_IN && qtype == DNS_QTYPE_AAAA) {
                            if (off + sizeof(struct in6_addr) <= *datalen)
                                inet_ntop(AF_INET6, data + off, rd, sizeof(rd));
                            else
                                return;
                        }

                        dns_resolved(args, qname, name, rd, ttl);
                        log_android(ANDROID_LOG_DEBUG,
                                    "DNS answer %d qname %s qtype %d ttl %d data %s",
                                    a, name, qtype, ttl, rd);
                    } else if (qclass == DNS_QCLASS_IN &&
                               (qtype == DNS_SVCB || qtype == DNS_HTTPS)) {
                        // https://tools.ietf.org/id/draft-ietf-dnsop-svcb-https-01.html
                        svcb = 1;
                        log_android(ANDROID_LOG_WARN,
                                    "SVCB answer %d qname %s qtype %d", a, name, qtype);
                    } else
                        log_android(ANDROID_LOG_DEBUG,
                                    "DNS answer %d qname %s qclass %d qtype %d ttl %d length %d",
                                    a, name, qclass, qtype, ttl, rdlength);

                    off += rdlength;
                } else {
                    log_android(ANDROID_LOG_WARN,
                                "DNS response A invalid off %d rdlength %d datalen %d",
                                off, rdlength, *datalen);
                    return;
                }
            } else {
                log_android(ANDROID_LOG_WARN,
                            "DNS response A invalid off %d datalen %d", off, *datalen);
                return;
            }
        }

        if (qcount > 0 &&
            (svcb || is_domain_blocked(args, qname))) {
            dns->qr = 1;
            dns->aa = 0;
            dns->tc = 0;
            dns->rd = 0;
            dns->ra = 0;
            dns->z = 0;
            dns->ad = 0;
            dns->cd = 0;
            dns->rcode = (uint16_t) args->rcode;
            dns->ans_count = 0;
            dns->auth_count = 0;
            dns->add_count = 0;
            *datalen = aoff;

            int version;
            char source[INET6_ADDRSTRLEN + 1];
            char dest[INET6_ADDRSTRLEN + 1];
            uint16_t sport;
            uint16_t dport;

            if (s->protocol == IPPROTO_UDP) {
                version = s->udp.version;
                sport = ntohs(s->udp.source);
                dport = ntohs(s->udp.dest);
                if (s->udp.version == 4) {
                    inet_ntop(AF_INET, &s->udp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->udp.daddr.ip4, dest, sizeof(dest));
                } else {
                    inet_ntop(AF_INET6, &s->udp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->udp.daddr.ip6, dest, sizeof(dest));
                }
            } else {
                version = s->tcp.version;
                sport = ntohs(s->tcp.source);
                dport = ntohs(s->tcp.dest);
                if (s->tcp.version == 4) {
                    inet_ntop(AF_INET, &s->tcp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->tcp.daddr.ip4, dest, sizeof(dest));
                } else {
                    inet_ntop(AF_INET6, &s->tcp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->tcp.daddr.ip6, dest, sizeof(dest));
                }
            }

            // Log qname
            char name[DNS_QNAME_MAX + 40 + 1];
            sprintf(name, "qtype %d qname %s rcode %d", qtype, qname, dns->rcode);
            jobject objPacket = create_packet(
                    args, version, s->protocol, "",
                    source, sport, dest, dport,
                    name, 0, 0);
            log_packet(args, objPacket);
        }
    } else if (acount > 0)
        log_android(ANDROID_LOG_WARN,
                    "DNS response qr %d opcode %d qcount %d acount %d",
                    dns->qr, dns->opcode, qcount, acount);
}
