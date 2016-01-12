#include <jni.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <android/log.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

// This should go into a header file later

// https://www.gasmi.net/hpd/
// Ethernet frame: 0800 2086 354b 00e0 f726 3fe9 0800

#define TAG "NetGuard.JNI"
#define MAXPKT 32768
#define TIMEOUTPKT 30
#define TTL 64

struct connection {
    time_t time;
    __be32 remote_seq; // host notation
    __be32 local_seq; // host notation
    int32_t saddr; // network notation
    __be16 source; // network notation
    int32_t daddr; // network notation
    __be16 dest; // network notation
    int state;
    int socket;
    int lport; // host notation
    struct connection *next;
};

void poll();

void handle_tcp(JNIEnv *, jobject, jbyte *, int);

void decode(JNIEnv *env, jobject instance, jbyte *, int);

int getUid(int, int, void *, int);

unsigned short checksum(unsigned short *, int);

char *hex(jbyte *, int);

int tun;
struct connection *connection = NULL;

// JNI interface

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Init");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1tun(JNIEnv *env, jobject instance, jint fd) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "tun");
    tun = fd;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1decode(JNIEnv *env, jobject instance,
                                                      jbyteArray buffer_, jint length) {
    jbyte *buffer = (*env)->GetByteArrayElements(env, buffer_, NULL);
    decode(env, instance, buffer, length);
    (*env)->ReleaseByteArrayElements(env, buffer_, buffer, 0);
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1receive(JNIEnv *env, jobject instance, jint fd) {
    int len;
    jbyte buffer[MAXPKT];
    while (1) {
        len = read(fd, buffer, sizeof(buffer));
        if (len < 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "Receive error=%d", len);
            return;

        } else if (len > 0)
            decode(env, instance, buffer, len);

        else
            __android_log_print(ANDROID_LOG_WARN, TAG, "Nothing received");
    }
}

// Private functions

void poll() {
    time_t now = time(NULL);

    struct connection *last = NULL;
    struct connection *cur = connection;
    while (cur != NULL) {
        // Log
        char dest[20];
        inet_ntop(AF_INET, &(cur->daddr), dest, sizeof(dest));

        if (cur->state == TCP_CLOSE || cur->time + TIMEOUTPKT < now) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Close/timeout %s/%u lport=%u",
                                dest, ntohs(cur->dest), cur->lport);

            shutdown(cur->socket, SHUT_RDWR);

            if (last == NULL)
                connection = cur->next;
            else
                last->next = cur->next;

            free(cur);

        } else {
            if (cur->state == TCP_SYN_RECV) {
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "Poll %s/%u lport=%u",
                                    dest, ntohs(cur->dest), cur->lport);

                // Check connection state
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(cur->socket, &wfds);
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                int ready = select(cur->socket + 1, NULL, &wfds, NULL, &tv);
                if (ready < 0) {
                    // TODO
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "select error %d: %s",
                                        errno, strerror(errno));
                    continue;
                }

                // Connected
                if (ready == 1) {
                    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Established ready=%d", ready);

                    int serr;
                    int optlen = sizeof(serr);
                    if (getsockopt(cur->socket, SOL_SOCKET, SO_ERROR, &serr, &optlen) < 0) {
                        // TODO
                        __android_log_print(ANDROID_LOG_ERROR, TAG, "getsockopt error %d: %s",
                                            errno, strerror(errno));
                        cur->state = TCP_CLOSE;
                        continue;
                    }
                    if (serr) {
                        // TODO
                        __android_log_print(ANDROID_LOG_ERROR, TAG, "SO_ERROR %d: %s",
                                            serr, strerror(serr));
                        cur->state = TCP_CLOSE;
                        continue;
                    }

                    // Send ACK
                    // -> SYN seq=x
                    // <- SYN-ACK ack=x+1 seq=y
                    // -> ACK=y+1 seq=x+1

                    // Build packet
                    int len = sizeof(struct iphdr) + sizeof(struct tcphdr); // no data
                    jbyte *buffer = calloc(len, 1); // TODO free
                    struct iphdr *ip = buffer;
                    struct tcphdr *tcp = buffer + sizeof(struct iphdr);

                    // Build IP header
                    ip->version = 4;
                    ip->ihl = sizeof(struct iphdr) >> 2;
                    ip->tot_len = htons(len);
                    ip->ttl = TTL;
                    ip->protocol = IPPROTO_TCP;
                    ip->saddr = cur->daddr;
                    ip->daddr = cur->saddr;

                    // Calculate IP checksum
                    ip->check = checksum(ip, sizeof(struct iphdr));

                    // Build TCP header
                    tcp->source = cur->dest;
                    tcp->dest = cur->source;
                    tcp->seq = htonl(cur->local_seq);
                    tcp->ack_seq = htonl(cur->remote_seq + 1); // TODO proper wrap around
                    tcp->doff = sizeof(struct tcphdr) >> 2;
                    tcp->syn = 1;
                    tcp->ack = 1;

                    // Calculate TCP checksum
                    int clen = sizeof(struct ippseudo) + sizeof(struct tcphdr);
                    jbyte csum[clen];

                    // Build pseudo header
                    struct ippseudo *pseudo = csum;
                    pseudo->ippseudo_src.s_addr = ip->saddr;
                    pseudo->ippseudo_dst.s_addr = ip->daddr;
                    pseudo->ippseudo_pad = 0;
                    pseudo->ippseudo_p = ip->protocol;
                    pseudo->ippseudo_len = htons(sizeof(struct tcphdr)); // no data

                    // Copy TCP header
                    memcpy(csum + sizeof(struct ippseudo), tcp, sizeof(struct tcphdr));

                    tcp->check = checksum(csum, clen);

                    char to[20];
                    inet_ntop(AF_INET, &(ip->daddr), to, sizeof(to));

                    // Send packet
                    __android_log_print(ANDROID_LOG_DEBUG, TAG,
                                        "Sending SYN+ACK to tun %s/%u ack %u len %d %s",
                                        to, ntohs(tcp->dest), ntohl(tcp->ack_seq), len,
                                        hex(buffer, len));
                    if (write(tun, buffer, len) < 0) {
                        // TODO
                        __android_log_print(ANDROID_LOG_ERROR, TAG, "write error %d: %s",
                                            errno, strerror(errno));
                    }

                    free(buffer);

                    cur->state = TCP_SYN_SENT;
                } else {
                    // TODO
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "Connecting ready=%d", ready);
                }
            }
        }

        cur = cur->next;
    }
}

void handle_tcp(JNIEnv *env, jobject instance, jbyte *buffer, int len) {
    // Check version
    jbyte version = (*buffer) >> 4;
    if (version != 4)
        return;

    // Copy buffer
    jbyte *copy = malloc(len); // TODO free
    memcpy(copy, buffer, len);

    // Get headers
    struct iphdr *iphdr = copy;
    jbyte optlen = (iphdr->ihl > 5 ? copy[20] : 0);
    struct tcphdr *tcphdr = buffer + (20 + optlen) * sizeof(jbyte);

    // Search connection
    struct connection *last = NULL;
    struct connection *cur = connection;
    while (cur != NULL && !(cur->saddr == iphdr->saddr && cur->source != tcphdr->source)) {
        last = cur;
        cur = cur->next;
    }

    // Log
    char dest[20];
    inet_ntop(AF_INET, &(iphdr->daddr), dest, sizeof(dest));

    if (cur == NULL) {
        if (tcphdr->syn) {
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYN %s/%u seq %u", dest,
                                ntohs(tcphdr->dest), ntohl(tcphdr->seq));

            // Register connection
            struct connection *syn = malloc(sizeof(struct connection));
            syn->time = time(NULL);
            syn->remote_seq = ntohl(tcphdr->seq);
            syn->local_seq = 123;  // TODO randomize
            syn->saddr = iphdr->saddr;
            syn->source = tcphdr->source;
            syn->daddr = iphdr->daddr;
            syn->dest = tcphdr->dest;
            syn->state = TCP_SYN_RECV;
            syn->next = NULL;

            if (last == NULL)
                connection = syn;
            else
                last->next = syn;

            // Get TCP socket
            if ((syn->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                // TODO
                __android_log_print(ANDROID_LOG_ERROR, TAG, "socket error %d: %s",
                                    errno, strerror(errno));
                syn->state = TCP_CLOSE;
                return;
            }

            // Set non blocking
            int flags = fcntl(syn->socket, F_GETFL, 0);
            if (flags < 0 || fcntl(syn->socket, F_SETFL, flags | O_NONBLOCK) < 0) {
                // TODO
                __android_log_print(ANDROID_LOG_ERROR, TAG, "fcntl error %d: %s",
                                    errno, strerror(errno));
                syn->state = TCP_CLOSE;
                return;
            }

            // Protect
            jclass cls = (*env)->GetObjectClass(env, instance);
            jmethodID mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
            if (mid == 0) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "protect not found");
                syn->state = TCP_CLOSE;
                return;
            }
            else {
                jboolean isProtected = (*env)->CallBooleanMethod(env, instance, mid, syn->socket);
                if (!isProtected)
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "protect failed");

                jthrowable ex = (*env)->ExceptionOccurred(env);
                if (ex) {
                    (*env)->ExceptionDescribe(env);
                    (*env)->ExceptionClear(env);
                    (*env)->DeleteLocalRef(env, ex);
                }
            }

            // Build target address
            struct sockaddr_in a;
            memset(&a, 0, sizeof(struct sockaddr_in));
            a.sin_family = AF_INET;
            a.sin_port = tcphdr->dest;
            a.sin_addr.s_addr = iphdr->daddr;

            // Initiate connect
            int err = connect(syn->socket, &a, sizeof(struct sockaddr_in));
            if (err < 0 && errno != EINPROGRESS) {
                // TODO
                __android_log_print(ANDROID_LOG_ERROR, TAG, "connect error %d: %s",
                                    errno, strerror(errno));
                syn->state = TCP_CLOSE;
                return;
            }

            // Get local port
            struct sockaddr_in sin;
            int sinlen = sizeof(sin);
            if (getsockname(syn->socket, &sin, &sinlen) < 0)
                __android_log_print(ANDROID_LOG_ERROR, TAG, "getsockname error %d: %s",
                                    errno, strerror(errno));
            else
                syn->lport = ntohs(sin.sin_port);

            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Connecting to %s/%u lport %u",
                                dest, ntohs(tcphdr->dest), syn->lport);
        }
    }
    else {
        cur->time = time(NULL);

        if (tcphdr->syn) {
            // TODO
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYNx2 %s/%u", dest, ntohs(tcphdr->dest));
        }
        else if (tcphdr->ack) {
            // TODO
            // check seq
            // check ack
            if (cur->state == TCP_SYN_SENT)
                cur->state = TCP_ESTABLISHED;
        }

        shutdown(cur->socket, SHUT_RDWR);
    }
}

void decode(JNIEnv *env, jobject instance, jbyte *buffer, int length) {
    jbyte protocol;
    void *saddr;
    void *daddr;
    char source[40];
    char dest[40];
    char flags[10];
    int flen = 0;
    jbyte *payload;

    // Get protocol, addresses & payload
    jbyte version = (*buffer) >> 4;
    if (version == 4) {
        struct iphdr *ip4hdr = buffer;

        protocol = ip4hdr->protocol;
        saddr = &ip4hdr->saddr;
        daddr = &ip4hdr->daddr;

        if (ip4hdr->frag_off & IP_MF)
            flags[flen++] = '+';

        jbyte optlen = (ip4hdr->ihl > 5 ? buffer[20] : 0);
        payload = buffer + 20 + optlen;

        uint16_t csum = checksum(ip4hdr, sizeof(struct iphdr));
        if (csum != 0) {
            // TODO checksum
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid IP checksum");
        }
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = buffer;

        protocol = ip6hdr->ip6_nxt;
        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;

        payload = buffer + 40;

        // TODO checksum
    }
    else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown version %d", version);
        return;
    }

    inet_ntop(version == 4 ? AF_INET : AF_INET6, saddr, source, sizeof(source));
    inet_ntop(version == 4 ? AF_INET : AF_INET6, daddr, dest, sizeof(dest));

    // Get ports & flags
    int sport = -1;
    int dport = -1;
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = payload;

        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);

        if (tcp->syn)
            flags[flen++] = 'S';
        if (tcp->ack)
            flags[flen++] = 'A';
        if (tcp->psh)
            flags[flen++] = 'P';
        if (tcp->fin)
            flags[flen++] = 'F';
        if (tcp->fin)
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
    int uid = -1;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        // Sleep 10 ms
        struct timespec tim, tim2;
        tim.tv_sec = 0;
        tim.tv_nsec = 10000000L;
        nanosleep(&tim, &tim2);

        // Lookup uid
        uid = getUid(protocol, version, saddr, sport);
        if (uid < 0 && version == 4) {
            int8_t saddr128[16];
            memset(saddr128, 0, 10);
            saddr128[10] = 0xFF;
            saddr128[11] = 0xFF;
            memcpy(saddr128 + 12, saddr, 4);
            uid = getUid(protocol, 6, saddr128, sport);
        }
    }

    __android_log_print(ANDROID_LOG_DEBUG, TAG,
                        "Packet v%d %s/%u -> %s/%u proto %d flags %s uid %d",
                        version, source, sport, dest, dport, protocol, flags, uid);
    poll();
    if (protocol == IPPROTO_TCP)
        handle_tcp(env, instance, buffer, length);

    // Call back
    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(env, cls, "logPacket",
                                        "(ILjava/lang/String;ILjava/lang/String;IILjava/lang/String;I)V");
    if (mid == 0)
        __android_log_print(ANDROID_LOG_ERROR, TAG, "logPacket not found");
    else {
        jstring jsource = (*env)->NewStringUTF(env, source);
        jstring jdest = (*env)->NewStringUTF(env, dest);
        jstring jflags = (*env)->NewStringUTF(env, flags);
        (*env)->CallVoidMethod(env, instance, mid,
                               version, jsource, sport, jdest, dport, protocol, jflags, uid);
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
}

int getUid(int protocol, int version, void *saddr, int sport) {
    char line[250];
    int fields;
    int32_t addr32;
    int8_t addr128[16];
    int port;
    int uid = -1;

    // Get proc file name
    char *fn = NULL;
    if (protocol == IPPROTO_TCP)
        fn = (version == 4 ? "/proc/net/tcp" : "/proc/net/tcp6");
    else if (protocol == IPPROTO_UDP)
        fn = (version == 4 ? "/proc/net/udp" : "/proc/net/udp6");
    else
        return -1;

    // Open proc file
    FILE *fd = fopen(fn, "r");
    if (fd == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Error opening %s", fn);
        return -1;
    }

    // Scan proc file
    int i = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (i++) {
            if (version == 4)
                fields = sscanf(line,
                                "%*d: %X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                                &addr32, &port, &uid);
            else
                fields = sscanf(line,
                                "%*d: %8X%8X%8X%8X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                                addr128, addr128 + 4, addr128 + 8, addr128 + 12, &port, &uid);

            if (fields < 3) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Invalid field #%d: %s", fields, line);
                break;
            }

            if (port == sport) {
                if (version == 4) {
                    if (addr32 == *((int32_t *) saddr))
                        return uid;
                }
                else {
                    if (memcmp(addr128, saddr, (size_t) 16) == 0)
                        return uid;
                }
            }
        }
    }

    fclose(fd);

    return -1;
}

unsigned short checksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    /*
    * Our algorithm is simple, using a 32-bit accumulator (sum),
    * we add sequential 16-bit words to it, and at the end, fold back
    * all the carry bits from the top 16 bits into the lower 16 bits.
    */

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}

char *hex(jbyte *data, int len) {
    char hex_str[] = "0123456789abcdef";

    char *out;
    out = (char *) malloc(len * 2 + 1);
    (out)[len * 2] = 0;

    if (!len) return NULL;

    for (size_t i = 0; i < len; i++) {
        (out)[i * 2 + 0] = hex_str[(data[i] >> 4) & 0x0F];
        (out)[i * 2 + 1] = hex_str[(data[i]) & 0x0F];
    }
    return out;
}