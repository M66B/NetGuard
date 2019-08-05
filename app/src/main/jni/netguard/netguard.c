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

// It is assumed that no packets will get lost and that packets arrive in order
// https://android.googlesource.com/platform/frameworks/base.git/+/master/services/core/jni/com_android_server_connectivity_Vpn.cpp

// Global variables

char socks5_addr[INET6_ADDRSTRLEN + 1];
int socks5_port = 0;
char socks5_username[127 + 1];
char socks5_password[127 + 1];
int loglevel = ANDROID_LOG_WARN;

extern int max_tun_msg;

extern FILE *pcap_file;
extern size_t pcap_record_size;
extern long pcap_file_size;

extern int uid_cache_size;
extern struct uid_cache_entry *uid_cache;

// JNI

jclass clsPacket;
jclass clsAllowed;
jclass clsRR;
jclass clsUsage;

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI load");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
        return -1;
    }

    const char *packet = "eu/faircode/netguard/Packet";
    clsPacket = jniGlobalRef(env, jniFindClass(env, packet));
    ng_add_alloc(clsPacket, "clsPacket");

    const char *allowed = "eu/faircode/netguard/Allowed";
    clsAllowed = jniGlobalRef(env, jniFindClass(env, allowed));
    ng_add_alloc(clsAllowed, "clsAllowed");

    const char *rr = "eu/faircode/netguard/ResourceRecord";
    clsRR = jniGlobalRef(env, jniFindClass(env, rr));
    ng_add_alloc(clsRR, "clsRR");

    const char *usage = "eu/faircode/netguard/Usage";
    clsUsage = jniGlobalRef(env, jniFindClass(env, usage));
    ng_add_alloc(clsUsage, "clsUsage");

    // Raise file number limit to maximum
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim))
        log_android(ANDROID_LOG_WARN, "getrlimit error %d: %s", errno, strerror(errno));
    else {
        rlim_t soft = rlim.rlim_cur;
        rlim.rlim_cur = rlim.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rlim))
            log_android(ANDROID_LOG_WARN, "setrlimit error %d: %s", errno, strerror(errno));
        else
            log_android(ANDROID_LOG_WARN, "raised file limit from %d to %d", soft, rlim.rlim_cur);
    }

    return JNI_VERSION_1_6;
}

void JNI_OnUnload(JavaVM *vm, void *reserved) {
    log_android(ANDROID_LOG_INFO, "JNI unload");

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK)
        log_android(ANDROID_LOG_INFO, "JNI load GetEnv failed");
    else {
        (*env)->DeleteGlobalRef(env, clsPacket);
        (*env)->DeleteGlobalRef(env, clsAllowed);
        (*env)->DeleteGlobalRef(env, clsRR);
        (*env)->DeleteGlobalRef(env, clsUsage);
        ng_delete_alloc(clsPacket, __FILE__, __LINE__);
        ng_delete_alloc(clsAllowed, __FILE__, __LINE__);
        ng_delete_alloc(clsRR, __FILE__, __LINE__);
        ng_delete_alloc(clsUsage, __FILE__, __LINE__);
    }
}

// JNI ServiceSinkhole

JNIEXPORT jlong JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1init(
        JNIEnv *env, jobject instance, jint sdk) {
    struct context *ctx = ng_calloc(1, sizeof(struct context), "init");
    ctx->sdk = sdk;

    loglevel = ANDROID_LOG_WARN;

    *socks5_addr = 0;
    socks5_port = 0;
    *socks5_username = 0;
    *socks5_password = 0;
    pcap_file = NULL;

    if (pthread_mutex_init(&ctx->lock, NULL))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_init failed");

    // Create signal pipe
    if (pipe(ctx->pipefds))
        log_android(ANDROID_LOG_ERROR, "Create pipe error %d: %s", errno, strerror(errno));
    else
        for (int i = 0; i < 2; i++) {
            int flags = fcntl(ctx->pipefds[i], F_GETFL, 0);
            if (flags < 0 || fcntl(ctx->pipefds[i], F_SETFL, flags | O_NONBLOCK) < 0)
                log_android(ANDROID_LOG_ERROR, "fcntl pipefds[%d] O_NONBLOCK error %d: %s",
                            i, errno, strerror(errno));
        }

    return (jlong) ctx;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1start(
        JNIEnv *env, jobject instance, jlong context, jint loglevel_) {
    struct context *ctx = (struct context *) context;

    loglevel = loglevel_;
    max_tun_msg = 0;
    ctx->stopping = 0;

    log_android(ANDROID_LOG_WARN, "Starting level %d", loglevel);

}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1run(
        JNIEnv *env, jobject instance, jlong context, jint tun, jboolean fwd53, jint rcode) {
    struct context *ctx = (struct context *) context;

    log_android(ANDROID_LOG_WARN, "Running tun %d fwd53 %d level %d", tun, fwd53, loglevel);

    // Set blocking
    int flags = fcntl(tun, F_GETFL, 0);
    if (flags < 0 || fcntl(tun, F_SETFL, flags & ~O_NONBLOCK) < 0)
        log_android(ANDROID_LOG_ERROR, "fcntl tun ~O_NONBLOCK error %d: %s",
                    errno, strerror(errno));

    // Get arguments
    struct arguments *args = ng_malloc(sizeof(struct arguments), "arguments");
    args->env = env;
    args->instance = instance;
    args->tun = tun;
    args->fwd53 = fwd53;
    args->rcode = rcode;
    args->ctx = ctx;
    handle_events(args);
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1stop(
        JNIEnv *env, jobject instance, jlong context) {
    struct context *ctx = (struct context *) context;
    ctx->stopping = 1;

    log_android(ANDROID_LOG_WARN, "Write pipe wakeup");
    if (write(ctx->pipefds[1], "w", 1) < 0)
        log_android(ANDROID_LOG_WARN, "Write pipe error %d: %s", errno, strerror(errno));
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1clear(
        JNIEnv *env, jobject instance, jlong context) {
    struct context *ctx = (struct context *) context;
    clear(ctx);
}

JNIEXPORT jint JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1get_1mtu(JNIEnv *env, jobject instance) {
    return get_mtu();
}

JNIEXPORT jintArray JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1get_1stats(
        JNIEnv *env, jobject instance, jlong context) {
    struct context *ctx = (struct context *) context;

    if (pthread_mutex_lock(&ctx->lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    jintArray jarray = (*env)->NewIntArray(env, 5);
    jint *jcount = (*env)->GetIntArrayElements(env, jarray, NULL);

    struct ng_session *s = ctx->ng_session;
    while (s != NULL) {
        if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
            if (!s->icmp.stop)
                jcount[0]++;
        } else if (s->protocol == IPPROTO_UDP) {
            if (s->udp.state == UDP_ACTIVE)
                jcount[1]++;
        } else if (s->protocol == IPPROTO_TCP) {
            if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE)
                jcount[2]++;
        }
        s = s->next;
    }

    if (pthread_mutex_unlock(&ctx->lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");

    jcount[3] = 0;
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL)
            if (dir->d_type != DT_DIR)
                jcount[3]++;
        closedir(d);
    }

    struct rlimit rlim;
    memset(&rlim, 0, sizeof(struct rlimit));
    getrlimit(RLIMIT_NOFILE, &rlim);
    jcount[4] = (jint) rlim.rlim_cur;

    (*env)->ReleaseIntArrayElements(env, jarray, jcount, 0);
    return jarray;
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1pcap(
        JNIEnv *env, jclass type,
        jstring name_, jint record_size, jint file_size) {

    pcap_record_size = (size_t) record_size;
    pcap_file_size = file_size;

    //if (pthread_mutex_lock(&lock))
    //    log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    if (name_ == NULL) {
        if (pcap_file != NULL) {
            int flags = fcntl(fileno(pcap_file), F_GETFL, 0);
            if (flags < 0 || fcntl(fileno(pcap_file), F_SETFL, flags & ~O_NONBLOCK) < 0)
                log_android(ANDROID_LOG_ERROR, "PCAP fcntl ~O_NONBLOCK error %d: %s",
                            errno, strerror(errno));

            if (fsync(fileno(pcap_file)))
                log_android(ANDROID_LOG_ERROR, "PCAP fsync error %d: %s", errno, strerror(errno));

            if (fclose(pcap_file))
                log_android(ANDROID_LOG_ERROR, "PCAP fclose error %d: %s", errno, strerror(errno));

            pcap_file = NULL;
        }
        log_android(ANDROID_LOG_WARN, "PCAP disabled");
    } else {
        const char *name = (*env)->GetStringUTFChars(env, name_, 0);
        ng_add_alloc(name, "name");
        log_android(ANDROID_LOG_WARN, "PCAP file %s record size %d truncate @%ld",
                    name, pcap_record_size, pcap_file_size);

        pcap_file = fopen(name, "ab+");
        if (pcap_file == NULL)
            log_android(ANDROID_LOG_ERROR, "PCAP fopen error %d: %s", errno, strerror(errno));
        else {
            int flags = fcntl(fileno(pcap_file), F_GETFL, 0);
            if (flags < 0 || fcntl(fileno(pcap_file), F_SETFL, flags | O_NONBLOCK) < 0)
                log_android(ANDROID_LOG_ERROR, "PCAP fcntl O_NONBLOCK error %d: %s",
                            errno, strerror(errno));

            long size = ftell(pcap_file);
            if (size == 0) {
                log_android(ANDROID_LOG_WARN, "PCAP initialize");
                write_pcap_hdr();
            } else
                log_android(ANDROID_LOG_WARN, "PCAP current size %ld", size);
        }

        (*env)->ReleaseStringUTFChars(env, name_, name);
        ng_delete_alloc(name, __FILE__, __LINE__);
    }

    //if (pthread_mutex_unlock(&lock))
    //    log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1socks5(JNIEnv *env, jobject instance, jstring addr_,
                                                      jint port, jstring username_,
                                                      jstring password_) {
    const char *addr = (*env)->GetStringUTFChars(env, addr_, 0);
    const char *username = (*env)->GetStringUTFChars(env, username_, 0);
    const char *password = (*env)->GetStringUTFChars(env, password_, 0);
    ng_add_alloc(addr, "addr");
    ng_add_alloc(username, "username");
    ng_add_alloc(password, "password");

    strcpy(socks5_addr, addr);
    socks5_port = port;
    strcpy(socks5_username, username);
    strcpy(socks5_password, password);

    log_android(ANDROID_LOG_WARN, "SOCKS5 %s:%d user=%s",
                socks5_addr, socks5_port, socks5_username);

    (*env)->ReleaseStringUTFChars(env, addr_, addr);
    (*env)->ReleaseStringUTFChars(env, username_, username);
    (*env)->ReleaseStringUTFChars(env, password_, password);
    ng_delete_alloc(addr, __FILE__, __LINE__);
    ng_delete_alloc(username, __FILE__, __LINE__);
    ng_delete_alloc(password, __FILE__, __LINE__);
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_ServiceSinkhole_jni_1done(
        JNIEnv *env, jobject instance, jlong context) {
    struct context *ctx = (struct context *) context;
    log_android(ANDROID_LOG_INFO, "Done");

    clear(ctx);

    if (pthread_mutex_destroy(&ctx->lock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_destroy failed");

    for (int i = 0; i < 2; i++)
        if (close(ctx->pipefds[i]))
            log_android(ANDROID_LOG_ERROR, "Close pipe error %d: %s", errno, strerror(errno));

    if (uid_cache != NULL)
        ng_free(uid_cache, __FILE__, __LINE__);
    uid_cache_size = 0;
    uid_cache = NULL;

    ng_free(ctx, __FILE__, __LINE__);
}

// JNI Util

JNIEXPORT jstring JNICALL
Java_eu_faircode_netguard_Util_jni_1getprop(JNIEnv *env, jclass type, jstring name_) {
    const char *name = (*env)->GetStringUTFChars(env, name_, 0);
    ng_add_alloc(name, "name");

    char value[PROP_VALUE_MAX + 1] = "";
    __system_property_get(name, value);

    (*env)->ReleaseStringUTFChars(env, name_, name);
    ng_delete_alloc(name, __FILE__, __LINE__);

    return (*env)->NewStringUTF(env, value); // Freed by Java
}

JNIEXPORT jboolean JNICALL
Java_eu_faircode_netguard_Util_is_1numeric_1address(JNIEnv *env, jclass type, jstring ip_) {
    jboolean numeric = 0;
    const char *ip = (*env)->GetStringUTFChars(env, ip_, 0);
    ng_add_alloc(ip, "ip");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo *result;
    int err = getaddrinfo(ip, NULL, &hints, &result);
    if (err)
        log_android(ANDROID_LOG_DEBUG, "getaddrinfo(%s) error %d: %s", ip, err, gai_strerror(err));
    else
        numeric = (jboolean) (result != NULL);

    if (result != NULL)
        freeaddrinfo(result);

    (*env)->ReleaseStringUTFChars(env, ip_, ip);
    ng_delete_alloc(ip, __FILE__, __LINE__);
    return numeric;
}

void report_exit(const struct arguments *args, const char *fmt, ...) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(cls, "cls");
    jmethodID mid = jniGetMethodID(args->env, cls, "nativeExit", "(Ljava/lang/String;)V");

    jstring jreason = NULL;
    if (fmt != NULL) {
        char line[1024];
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        jreason = (*args->env)->NewStringUTF(args->env, line);
        ng_add_alloc(jreason, "jreason");
        va_end(argptr);
    }

    (*args->env)->CallVoidMethod(args->env, args->instance, mid, jreason);
    jniCheckException(args->env);

    if (jreason != NULL) {
        (*args->env)->DeleteLocalRef(args->env, jreason);
        ng_delete_alloc(jreason, __FILE__, __LINE__);
    }
    (*args->env)->DeleteLocalRef(args->env, cls);
    ng_delete_alloc(cls, __FILE__, __LINE__);
}

void report_error(const struct arguments *args, jint error, const char *fmt, ...) {
    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(cls, "cls");
    jmethodID mid = jniGetMethodID(args->env, cls, "nativeError", "(ILjava/lang/String;)V");

    jstring jreason = NULL;
    if (fmt != NULL) {
        char line[1024];
        va_list argptr;
        va_start(argptr, fmt);
        vsprintf(line, fmt, argptr);
        jreason = (*args->env)->NewStringUTF(args->env, line);
        ng_add_alloc(jreason, "jreason");
        va_end(argptr);
    }

    (*args->env)->CallVoidMethod(args->env, args->instance, mid, error, jreason);
    jniCheckException(args->env);

    if (jreason != NULL) {
        (*args->env)->DeleteLocalRef(args->env, jreason);
        ng_delete_alloc(jreason, __FILE__, __LINE__);
    }
    (*args->env)->DeleteLocalRef(args->env, cls);
    ng_delete_alloc(cls, __FILE__, __LINE__);
}

static jmethodID midProtect = NULL;

int protect_socket(const struct arguments *args, int socket) {
    if (args->ctx->sdk >= 21)
        return 0;

    jclass cls = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(cls, "cls");
    if (cls == NULL) {
        log_android(ANDROID_LOG_ERROR, "protect socket failed to get class");
        return -1;
    }

    if (midProtect == NULL)
        midProtect = jniGetMethodID(args->env, cls, "protect", "(I)Z");
    if (midProtect == NULL) {
        log_android(ANDROID_LOG_ERROR, "protect socket failed to get method");
        return -1;
    }

    jboolean isProtected = (*args->env)->CallBooleanMethod(
            args->env, args->instance, midProtect, socket);
    jniCheckException(args->env);

    if (!isProtected) {
        log_android(ANDROID_LOG_ERROR, "protect socket failed");
        return -1;
    }

    (*args->env)->DeleteLocalRef(args->env, cls);
    ng_delete_alloc(cls, __FILE__, __LINE__);

    return 0;
}

// http://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html
// http://journals.ecs.soton.ac.uk/java/tutorial/native1.1/implementing/index.html

jobject jniGlobalRef(JNIEnv *env, jobject cls) {
    jobject gcls = (*env)->NewGlobalRef(env, cls);
    if (gcls == NULL)
        log_android(ANDROID_LOG_ERROR, "Global ref failed (out of memory?)");
    return gcls;
}

jclass jniFindClass(JNIEnv *env, const char *name) {
    jclass cls = (*env)->FindClass(env, name);
    if (cls == NULL)
        log_android(ANDROID_LOG_ERROR, "Class %s not found", name);
    else
        jniCheckException(env);
    return cls;
}

jmethodID jniGetMethodID(JNIEnv *env, jclass cls, const char *name, const char *signature) {
    jmethodID method = (*env)->GetMethodID(env, cls, name, signature);
    if (method == NULL) {
        log_android(ANDROID_LOG_ERROR, "Method %s %s not found", name, signature);
        jniCheckException(env);
    }
    return method;
}

jfieldID jniGetFieldID(JNIEnv *env, jclass cls, const char *name, const char *type) {
    jfieldID field = (*env)->GetFieldID(env, cls, name, type);
    if (field == NULL)
        log_android(ANDROID_LOG_ERROR, "Field %s type %s not found", name, type);
    return field;
}

jobject jniNewObject(JNIEnv *env, jclass cls, jmethodID constructor, const char *name) {
    jobject object = (*env)->NewObject(env, cls, constructor);
    if (object == NULL)
        log_android(ANDROID_LOG_ERROR, "Create object %s failed", name);
    else
        jniCheckException(env);
    return object;
}

int jniCheckException(JNIEnv *env) {
    jthrowable ex = (*env)->ExceptionOccurred(env);
    if (ex) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, ex);
        ng_delete_alloc(ex, __FILE__, __LINE__);
        return 1;
    }
    return 0;
}

static jmethodID midLogPacket = NULL;

void log_packet(const struct arguments *args, jobject jpacket) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Leu/faircode/netguard/Packet;)V";
    if (midLogPacket == NULL)
        midLogPacket = jniGetMethodID(args->env, clsService, "logPacket", signature);

    (*args->env)->CallVoidMethod(args->env, args->instance, midLogPacket, jpacket);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jpacket);
    ng_delete_alloc(clsService, __FILE__, __LINE__);
    ng_delete_alloc(jpacket, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_packet %f", mselapsed);
#endif
}

static jmethodID midDnsResolved = NULL;
static jmethodID midInitRR = NULL;
jfieldID fidQTime = NULL;
jfieldID fidQName = NULL;
jfieldID fidAName = NULL;
jfieldID fidResource = NULL;
jfieldID fidTTL = NULL;

void dns_resolved(const struct arguments *args,
                  const char *qname, const char *aname, const char *resource, int ttl) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Leu/faircode/netguard/ResourceRecord;)V";
    if (midDnsResolved == NULL)
        midDnsResolved = jniGetMethodID(args->env, clsService, "dnsResolved", signature);

    const char *rr = "eu/faircode/netguard/ResourceRecord";
    if (midInitRR == NULL)
        midInitRR = jniGetMethodID(args->env, clsRR, "<init>", "()V");

    jobject jrr = jniNewObject(args->env, clsRR, midInitRR, rr);
    ng_add_alloc(jrr, "jrr");

    if (fidQTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidQTime = jniGetFieldID(args->env, clsRR, "Time", "J");
        fidQName = jniGetFieldID(args->env, clsRR, "QName", string);
        fidAName = jniGetFieldID(args->env, clsRR, "AName", string);
        fidResource = jniGetFieldID(args->env, clsRR, "Resource", string);
        fidTTL = jniGetFieldID(args->env, clsRR, "TTL", "I");
    }

    jlong jtime = time(NULL) * 1000LL;
    jstring jqname = (*args->env)->NewStringUTF(args->env, qname);
    jstring janame = (*args->env)->NewStringUTF(args->env, aname);
    jstring jresource = (*args->env)->NewStringUTF(args->env, resource);
    ng_add_alloc(jqname, "jqname");
    ng_add_alloc(janame, "janame");
    ng_add_alloc(jresource, "jresource");

    (*args->env)->SetLongField(args->env, jrr, fidQTime, jtime);
    (*args->env)->SetObjectField(args->env, jrr, fidQName, jqname);
    (*args->env)->SetObjectField(args->env, jrr, fidAName, janame);
    (*args->env)->SetObjectField(args->env, jrr, fidResource, jresource);
    (*args->env)->SetIntField(args->env, jrr, fidTTL, ttl);

    (*args->env)->CallVoidMethod(args->env, args->instance, midDnsResolved, jrr);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jresource);
    (*args->env)->DeleteLocalRef(args->env, janame);
    (*args->env)->DeleteLocalRef(args->env, jqname);
    (*args->env)->DeleteLocalRef(args->env, jrr);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    ng_delete_alloc(jresource, __FILE__, __LINE__);
    ng_delete_alloc(janame, __FILE__, __LINE__);
    ng_delete_alloc(jqname, __FILE__, __LINE__);
    ng_delete_alloc(jrr, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_packet %f", mselapsed);
#endif
}

static jmethodID midIsDomainBlocked = NULL;

jboolean is_domain_blocked(const struct arguments *args, const char *name) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Ljava/lang/String;)Z";
    if (midIsDomainBlocked == NULL)
        midIsDomainBlocked = jniGetMethodID(args->env, clsService, "isDomainBlocked", signature);

    jstring jname = (*args->env)->NewStringUTF(args->env, name);
    ng_add_alloc(jname, "jname");

    jboolean jallowed = (*args->env)->CallBooleanMethod(
            args->env, args->instance, midIsDomainBlocked, jname);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jname);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    ng_delete_alloc(jname, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "is_domain_blocked %f", mselapsed);
#endif

    return jallowed;
}

static jmethodID midGetUidQ = NULL;

jint get_uid_q(const struct arguments *args,
               jint version, jint protocol,
               const char *source, jint sport,
               const char *dest, jint dport) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(IILjava/lang/String;ILjava/lang/String;I)I";
    if (midGetUidQ == NULL)
        midGetUidQ = jniGetMethodID(args->env, clsService, "getUidQ", signature);

    jstring jsource = (*args->env)->NewStringUTF(args->env, source);
    jstring jdest = (*args->env)->NewStringUTF(args->env, dest);
    ng_add_alloc(jsource, "jsource");
    ng_add_alloc(jdest, "jdest");

    jint juid = (*args->env)->CallIntMethod(
            args->env, args->instance, midGetUidQ,
            version, protocol, jsource, sport, jdest, dport);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jdest);
    (*args->env)->DeleteLocalRef(args->env, jsource);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    ng_delete_alloc(jdest, __FILE__, __LINE__);
    ng_delete_alloc(jsource, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "get_uid_q %f", mselapsed);
#endif

    return juid;
}

static jmethodID midIsAddressAllowed = NULL;
jfieldID fidRaddr = NULL;
jfieldID fidRport = NULL;
struct allowed allowed;

struct allowed *is_address_allowed(const struct arguments *args, jobject jpacket) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Leu/faircode/netguard/Packet;)Leu/faircode/netguard/Allowed;";
    if (midIsAddressAllowed == NULL)
        midIsAddressAllowed = jniGetMethodID(args->env, clsService, "isAddressAllowed", signature);

    jobject jallowed = (*args->env)->CallObjectMethod(
            args->env, args->instance, midIsAddressAllowed, jpacket);
    ng_add_alloc(jallowed, "jallowed");
    jniCheckException(args->env);

    if (jallowed != NULL) {
        if (fidRaddr == NULL) {
            const char *string = "Ljava/lang/String;";
            fidRaddr = jniGetFieldID(args->env, clsAllowed, "raddr", string);
            fidRport = jniGetFieldID(args->env, clsAllowed, "rport", "I");
        }

        jstring jraddr = (*args->env)->GetObjectField(args->env, jallowed, fidRaddr);
        ng_add_alloc(jraddr, "jraddr");
        if (jraddr == NULL)
            *allowed.raddr = 0;
        else {
            const char *raddr = (*args->env)->GetStringUTFChars(args->env, jraddr, NULL);
            ng_add_alloc(raddr, "raddr");
            strcpy(allowed.raddr, raddr);
            (*args->env)->ReleaseStringUTFChars(args->env, jraddr, raddr);
            ng_delete_alloc(raddr, __FILE__, __LINE__);
        }
        allowed.rport = (uint16_t) (*args->env)->GetIntField(args->env, jallowed, fidRport);

        (*args->env)->DeleteLocalRef(args->env, jraddr);
        ng_delete_alloc(jraddr, __FILE__, __LINE__);
    }


    (*args->env)->DeleteLocalRef(args->env, jpacket);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    (*args->env)->DeleteLocalRef(args->env, jallowed);
    ng_delete_alloc(jpacket, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);
    ng_delete_alloc(jallowed, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "is_address_allowed %f", mselapsed);
#endif

    return (jallowed == NULL ? NULL : &allowed);
}

jmethodID midInitPacket = NULL;

jfieldID fidTime = NULL;
jfieldID fidVersion = NULL;
jfieldID fidProtocol = NULL;
jfieldID fidFlags = NULL;
jfieldID fidSaddr = NULL;
jfieldID fidSport = NULL;
jfieldID fidDaddr = NULL;
jfieldID fidDport = NULL;
jfieldID fidData = NULL;
jfieldID fidUid = NULL;
jfieldID fidAllowed = NULL;

jobject create_packet(const struct arguments *args,
                      jint version,
                      jint protocol,
                      const char *flags,
                      const char *source,
                      jint sport,
                      const char *dest,
                      jint dport,
                      const char *data,
                      jint uid,
                      jboolean allowed) {
    JNIEnv *env = args->env;

#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    /*
        jbyte b[] = {1,2,3};
        jbyteArray ret = env->NewByteArray(3);
        env->SetByteArrayRegion (ret, 0, 3, b);
     */

    const char *packet = "eu/faircode/netguard/Packet";
    if (midInitPacket == NULL)
        midInitPacket = jniGetMethodID(env, clsPacket, "<init>", "()V");
    jobject jpacket = jniNewObject(env, clsPacket, midInitPacket, packet);
    ng_add_alloc(jpacket, "jpacket");

    if (fidTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidTime = jniGetFieldID(env, clsPacket, "time", "J");
        fidVersion = jniGetFieldID(env, clsPacket, "version", "I");
        fidProtocol = jniGetFieldID(env, clsPacket, "protocol", "I");
        fidFlags = jniGetFieldID(env, clsPacket, "flags", string);
        fidSaddr = jniGetFieldID(env, clsPacket, "saddr", string);
        fidSport = jniGetFieldID(env, clsPacket, "sport", "I");
        fidDaddr = jniGetFieldID(env, clsPacket, "daddr", string);
        fidDport = jniGetFieldID(env, clsPacket, "dport", "I");
        fidData = jniGetFieldID(env, clsPacket, "data", string);
        fidUid = jniGetFieldID(env, clsPacket, "uid", "I");
        fidAllowed = jniGetFieldID(env, clsPacket, "allowed", "Z");
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    jlong t = tv.tv_sec * 1000LL + tv.tv_usec / 1000;
    jstring jflags = (*env)->NewStringUTF(env, flags);
    jstring jsource = (*env)->NewStringUTF(env, source);
    jstring jdest = (*env)->NewStringUTF(env, dest);
    jstring jdata = (*env)->NewStringUTF(env, data);
    ng_add_alloc(jflags, "jflags");
    ng_add_alloc(jsource, "jsource");
    ng_add_alloc(jdest, "jdest");
    ng_add_alloc(jdata, "jdata");

    (*env)->SetLongField(env, jpacket, fidTime, t);
    (*env)->SetIntField(env, jpacket, fidVersion, version);
    (*env)->SetIntField(env, jpacket, fidProtocol, protocol);
    (*env)->SetObjectField(env, jpacket, fidFlags, jflags);
    (*env)->SetObjectField(env, jpacket, fidSaddr, jsource);
    (*env)->SetIntField(env, jpacket, fidSport, sport);
    (*env)->SetObjectField(env, jpacket, fidDaddr, jdest);
    (*env)->SetIntField(env, jpacket, fidDport, dport);
    (*env)->SetObjectField(env, jpacket, fidData, jdata);
    (*env)->SetIntField(env, jpacket, fidUid, uid);
    (*env)->SetBooleanField(env, jpacket, fidAllowed, allowed);

    (*env)->DeleteLocalRef(env, jdata);
    (*env)->DeleteLocalRef(env, jdest);
    (*env)->DeleteLocalRef(env, jsource);
    (*env)->DeleteLocalRef(env, jflags);
    ng_delete_alloc(jdata, __FILE__, __LINE__);
    ng_delete_alloc(jdest, __FILE__, __LINE__);
    ng_delete_alloc(jsource, __FILE__, __LINE__);
    ng_delete_alloc(jflags, __FILE__, __LINE__);
    // Caller needs to delete reference to packet

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "create_packet %f", mselapsed);
#endif

    return jpacket;
}

jmethodID midAccountUsage = NULL;
jmethodID midInitUsage = NULL;
jfieldID fidUsageTime = NULL;
jfieldID fidUsageVersion = NULL;
jfieldID fidUsageProtocol = NULL;
jfieldID fidUsageDAddr = NULL;
jfieldID fidUsageDPort = NULL;
jfieldID fidUsageUid = NULL;
jfieldID fidUsageSent = NULL;
jfieldID fidUsageReceived = NULL;

void account_usage(const struct arguments *args, jint version, jint protocol,
                   const char *daddr, jint dport, jint uid, jlong sent, jlong received) {
#ifdef PROFILE_JNI
    float mselapsed;
    struct timeval start, end;
    gettimeofday(&start, NULL);
#endif

    jclass clsService = (*args->env)->GetObjectClass(args->env, args->instance);
    ng_add_alloc(clsService, "clsService");

    const char *signature = "(Leu/faircode/netguard/Usage;)V";
    if (midAccountUsage == NULL)
        midAccountUsage = jniGetMethodID(args->env, clsService, "accountUsage", signature);

    const char *usage = "eu/faircode/netguard/Usage";
    if (midInitUsage == NULL)
        midInitUsage = jniGetMethodID(args->env, clsUsage, "<init>", "()V");

    jobject jusage = jniNewObject(args->env, clsUsage, midInitUsage, usage);
    ng_add_alloc(jusage, "jusage");

    if (fidUsageTime == NULL) {
        const char *string = "Ljava/lang/String;";
        fidUsageTime = jniGetFieldID(args->env, clsUsage, "Time", "J");
        fidUsageVersion = jniGetFieldID(args->env, clsUsage, "Version", "I");
        fidUsageProtocol = jniGetFieldID(args->env, clsUsage, "Protocol", "I");
        fidUsageDAddr = jniGetFieldID(args->env, clsUsage, "DAddr", string);
        fidUsageDPort = jniGetFieldID(args->env, clsUsage, "DPort", "I");
        fidUsageUid = jniGetFieldID(args->env, clsUsage, "Uid", "I");
        fidUsageSent = jniGetFieldID(args->env, clsUsage, "Sent", "J");
        fidUsageReceived = jniGetFieldID(args->env, clsUsage, "Received", "J");
    }

    jlong jtime = time(NULL) * 1000LL;
    jstring jdaddr = (*args->env)->NewStringUTF(args->env, daddr);
    ng_add_alloc(jdaddr, "jdaddr");

    (*args->env)->SetLongField(args->env, jusage, fidUsageTime, jtime);
    (*args->env)->SetIntField(args->env, jusage, fidUsageVersion, version);
    (*args->env)->SetIntField(args->env, jusage, fidUsageProtocol, protocol);
    (*args->env)->SetObjectField(args->env, jusage, fidUsageDAddr, jdaddr);
    (*args->env)->SetIntField(args->env, jusage, fidUsageDPort, dport);
    (*args->env)->SetIntField(args->env, jusage, fidUsageUid, uid);
    (*args->env)->SetLongField(args->env, jusage, fidUsageSent, sent);
    (*args->env)->SetLongField(args->env, jusage, fidUsageReceived, received);

    (*args->env)->CallVoidMethod(args->env, args->instance, midAccountUsage, jusage);
    jniCheckException(args->env);

    (*args->env)->DeleteLocalRef(args->env, jdaddr);
    (*args->env)->DeleteLocalRef(args->env, jusage);
    (*args->env)->DeleteLocalRef(args->env, clsService);
    ng_delete_alloc(jdaddr, __FILE__, __LINE__);
    ng_delete_alloc(jusage, __FILE__, __LINE__);
    ng_delete_alloc(clsService, __FILE__, __LINE__);

#ifdef PROFILE_JNI
    gettimeofday(&end, NULL);
    mselapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                (end.tv_usec - start.tv_usec) / 1000.0;
    if (mselapsed > PROFILE_JNI)
        log_android(ANDROID_LOG_WARN, "log_packet %f", mselapsed);
#endif
}

struct alloc_record {
    const char *tag;
    time_t time;
    void *ptr;
};

int allocs = 0;
int balance = 0;
struct alloc_record *alloc = NULL;
pthread_mutex_t *alock = NULL;

void ng_add_alloc(void *ptr, const char *tag) {
#ifdef PROFILE_MEMORY
    if (ptr == NULL)
        return;

    if (alock == NULL) {
        alock = malloc(sizeof(pthread_mutex_t));
        if (pthread_mutex_init(alock, NULL))
            log_android(ANDROID_LOG_ERROR, "pthread_mutex_init failed");
    }

    if (pthread_mutex_lock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    int c = 0;
    for (; c < allocs; c++)
        if (alloc[c].ptr == NULL)
            break;

    if (c >= allocs) {
        if (allocs == 0)
            alloc = malloc(sizeof(struct alloc_record));
        else
            alloc = realloc(alloc, sizeof(struct alloc_record) * (allocs + 1));
        c = allocs;
        allocs++;
    }

    alloc[c].tag = tag;
    alloc[c].time = time(NULL);
    alloc[c].ptr = ptr;
    balance++;

    if (pthread_mutex_unlock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");
#endif
}

void ng_delete_alloc(void *ptr, const char *file, int line) {
#ifdef PROFILE_MEMORY
    if (ptr == NULL)
        return;

    if (pthread_mutex_lock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    int found = 0;
    for (int c = 0; c < allocs; c++)
        if (alloc[c].ptr == ptr) {
            found = 1;
            alloc[c].tag = "[free]";
            alloc[c].ptr = NULL;
            break;
        }

    if (found == 1)
        balance--;

    log_android(found ? ANDROID_LOG_DEBUG : ANDROID_LOG_ERROR,
                "alloc/free balance %d records %d found %d", balance, allocs, found);
    if (found == 0)
        log_android(ANDROID_LOG_ERROR, "Not found at %s:%d", file, line);

    if (pthread_mutex_unlock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");
#endif
}

void *ng_malloc(size_t __byte_count, const char *tag) {
    void *ptr = malloc(__byte_count);
    ng_add_alloc(ptr, tag);
    return ptr;
}

void *ng_calloc(size_t __item_count, size_t __item_size, const char *tag) {
    void *ptr = calloc(__item_count, __item_size);
    ng_add_alloc(ptr, tag);
    return ptr;
}

void *ng_realloc(void *__ptr, size_t __byte_count, const char *tag) {
    ng_delete_alloc(__ptr, NULL, 0);
    void *ptr = realloc(__ptr, __byte_count);
    ng_add_alloc(ptr, tag);
    return ptr;
}

void ng_free(void *__ptr, const char *file, int line) {
    ng_delete_alloc(__ptr, file, line);
    free(__ptr);
}

void ng_dump() {
    int r = 0;
    for (int c = 0; c < allocs; c++)
        if (alloc[c].ptr != NULL)
            log_android(ANDROID_LOG_WARN,
                        "holding %d [%s] %s",
                        ++r, alloc[c].tag, ctime(&alloc[c].time));
}

JNIEXPORT void JNICALL
Java_eu_faircode_netguard_Util_dump_1memory_1profile(JNIEnv *env, jclass type) {
#ifdef PROFILE_MEMORY
    log_android(ANDROID_LOG_DEBUG, "Dump memory profile");

    if (pthread_mutex_lock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

    ng_dump();

    if (pthread_mutex_unlock(alock))
        log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");

#endif
}