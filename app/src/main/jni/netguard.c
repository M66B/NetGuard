#include <jni.h>
#include <stdio.h>
#include <stddef.h>
#include <malloc.h>
#include <unistd.h>
#include <android/log.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define TAG "NetGuard.JNI"
#define MAXPKT 32768

void decode(JNIEnv *env, jobject instance, jbyte *, int);

void scanproc6(const char *);

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Init", 1);
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
    jbyte *buffer = malloc(MAXPKT);
    while (1) {
        len = read(fd, buffer, MAXPKT);
        if (len < 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "Receive error %d", len);
            free(buffer);
            return;

        } else if (len > 0)
            decode(env, instance, buffer, len);

        else
            __android_log_print(ANDROID_LOG_WARN, TAG, "Nothing received");
    }
}

void decode(JNIEnv *env, jobject instance, jbyte *buffer, int length) {
    jbyte protocol = -1;
    char source[40];
    char dest[40];
    char flags[10];
    int flen = 0;
    void *payload = NULL;

    jbyte version = (*buffer) >> 4;
    if (version == 4) {
        struct iphdr *ip4hdr = buffer;
        protocol = ip4hdr->protocol;
        inet_ntop(AF_INET, &ip4hdr->saddr, source, sizeof(source));
        inet_ntop(AF_INET, &ip4hdr->daddr, dest, sizeof(dest));

        jbyte optlen = 0;
        if (ip4hdr->ihl > 5)
            optlen = buffer[20];
        payload = buffer + 20 * sizeof(jbyte) + optlen;
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = buffer;
        protocol = ip6hdr->ip6_nxt;
        inet_ntop(AF_INET6, &ip6hdr->ip6_src, source, sizeof(source));
        inet_ntop(AF_INET6, &ip6hdr->ip6_dst, dest, sizeof(dest));

        payload = buffer + 40 * sizeof(jbyte);
    }
    else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown version %d", version);
        *source = 0;
        *dest = 0;
    }

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

    __android_log_print(ANDROID_LOG_INFO, TAG, "Packet v%d %s/%d -> %s/%d proto %d flags %s",
                        version, source, sport, dest, dport, protocol, flags);
    //scanproc6("/proc/net/tcp6");

    jclass cls = (*env)->GetObjectClass(env, instance);
    jmethodID mid = (*env)->GetMethodID(env, cls, "logPacket",
                                        "(ILjava/lang/String;ILjava/lang/String;IILjava/lang/String;)V");
    if (mid != 0) {
        jstring jsource = (*env)->NewStringUTF(env, source);
        jstring jdest = (*env)->NewStringUTF(env, dest);
        jstring jflags = (*env)->NewStringUTF(env, flags);
        (*env)->CallVoidMethod(env, instance, mid,
                               version, jsource, sport, jdest, dport, protocol, jflags);
    }
}

void scanproc6(const char *file) {
    char line[500];
    struct in6_addr *saddr = malloc(sizeof(struct in6_addr));
    char source[40];
    int sport;
    int uid;
    FILE *fd = fopen(file, "r");
    if (fd != NULL) {
        int i = 0;
        while (fgets(line, 500, fd) != NULL) {
            if (i++) {
                sscanf(line,
                       "%*d: %8X%8X%8X%8X:%X %*X:%*X %*X %*lX:%*lX %*X:%*X %*X %d %*d %*ld ",
                       saddr, ((void *) saddr) + 4, ((void *) saddr) + 8, ((void *) saddr) + 12,
                       &sport, &uid);
                inet_ntop(AF_INET6, saddr, source, sizeof(source));
                __android_log_print(ANDROID_LOG_INFO, TAG, "proc %s/%d %d", source, sport, uid);
            }
        }
        fclose(fd);
    }
    free(saddr);
}