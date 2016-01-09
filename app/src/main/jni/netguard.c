#include <jni.h>
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

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1init(JNIEnv *env, jobject instance) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Init", 1);
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_SinkholeService_jni_1decode(JNIEnv *env, jobject instance,
                                                      jbyteArray buffer_) {
    jbyte *buffer = (*env)->GetByteArrayElements(env, buffer_, NULL);
    jbyte version = (*buffer) >> 4;

    if (version == 4) {
        struct iphdr *ip4hdr = buffer;
        __android_log_print(ANDROID_LOG_INFO, TAG, "Version 4 protocol %d", ip4hdr->protocol);
    }
    else if (version == 6) {
        struct ip6_hdr *ip6hdr = buffer;
        __android_log_print(ANDROID_LOG_INFO, TAG, "Version 6 protocol %d", ip6hdr->ip6_nxt);
    }
    else
        __android_log_print(ANDROID_LOG_WARN, TAG, "Unknown version %d", version);

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

        } else if (len > 0) {
            jbyte version = (*buffer) >> 4;

            jbyte protocol = -1;
            char source[40];
            char dest[40];
            void *payload = NULL;
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

            } else if (protocol == IPPROTO_UDP) {
                struct udphdr *udp = payload;
                sport = ntohs(udp->source);
                dport = ntohs(udp->dest);
            }

            __android_log_print(ANDROID_LOG_INFO, TAG, "%s/%d -> %s/%d",
                                source, sport, dest, dport);
        } else
            __android_log_print(ANDROID_LOG_WARN, TAG, "Nothing received");
    }
}
