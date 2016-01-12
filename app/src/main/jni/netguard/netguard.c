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

#define TAG "NetGuard.JNI"
#define MAXPKT 32768
#define TIMEOUTPKT 30

struct packet {
    void *data;
    struct packet *next;
};

struct connection {
    time_t time;
    int32_t saddr;
    __be16 source;
    int32_t daddr;
    __be16 dest;
    int state;
    int socket;
    int lport;
    struct packet *packet;
    struct connection *next;
};

struct connection *connection = NULL;

void decode(JNIEnv *env, jobject instance, jbyte *, int);

int getUid(int, int, void *, int);

void handle_tcp(JNIEnv *, jobject, jbyte *, int);

void poll();

// JNI interface

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Init");
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
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Close/timeout %s/%d lport=%d",
                                dest, ntohs(cur->dest), cur->lport);

            shutdown(cur->socket, SHUT_RDWR);

            if (last == NULL)
                connection = cur->next;
            else
                last->next = cur->next;

            free(cur->packet);
            free(cur);

        } else {
            if (cur->state == TCP_SYN_RECV) {
                __android_log_print(ANDROID_LOG_DEBUG, TAG, "Poll %s/%d lport=%d",
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
                    cur->state = TCP_ESTABLISHED;
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
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYN %s/%d", dest, ntohs(tcphdr->dest));

            // Register connection
            struct connection *syn = malloc(sizeof(struct connection));
            syn->time = time(NULL);
            syn->saddr = iphdr->saddr;
            syn->source = tcphdr->source;
            syn->daddr = iphdr->daddr;
            syn->dest = tcphdr->dest;
            syn->state = TCP_SYN_RECV;
            syn->packet = malloc(sizeof(struct packet));  // TODO free
            syn->packet->data = copy;
            syn->packet->next = NULL;
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

            __android_log_print(ANDROID_LOG_DEBUG, TAG, "Connecting to %s/%d lport=%d",
                                dest, ntohs(tcphdr->dest), syn->lport);
        }
    }
    else {
        cur->time = time(NULL);

        if (tcphdr->syn) {
            // TODO
            __android_log_print(ANDROID_LOG_DEBUG, TAG, "SYNx2 %s/%d", dest, ntohs(tcphdr->dest));
        }
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
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = buffer;

        protocol = ip6hdr->ip6_nxt;
        saddr = &ip6hdr->ip6_src;
        daddr = &ip6hdr->ip6_dst;

        payload = buffer + 40;
    }
    else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown version=%d", version);
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
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = payload;

        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);
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

    __android_log_print(ANDROID_LOG_DEBUG, TAG, "Packet v%d %s/%d -> %s/%d proto %d flags %s uid %d",
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