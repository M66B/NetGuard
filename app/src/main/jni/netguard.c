#include <jni.h>
#include <stddef.h>
#include <android/log.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define TAG "NetGuard.JNI"

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

unsigned short checksum(unsigned short *addr, int len) {
    unsigned short result;
    unsigned int sum = 0;

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(unsigned char *) addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

