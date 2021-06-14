#include "netguard.h"

extern char socks5_addr[INET6_ADDRSTRLEN + 1];
extern int socks5_port;
extern char socks5_username[127 + 1];
extern char socks5_password[127 + 1];
extern bool sock5_udp_relay_enabled;

int socks5_client_recv_cb(int socksfd, uint8_t *socks5_status,
                          int ipver, int type, void *bind_addr, __be16 *bind_port,
                          char *session) {
    uint8_t buffer[32];
    ssize_t bytes = recv(socksfd, buffer, sizeof(buffer), 0);
    if (bytes < 0) {
        log_android(ANDROID_LOG_ERROR, "%s recv SOCKS5 error %d: %s",
                    session, errno, strerror(errno));
        return -1;
    } else {
        char *h = hex(buffer, (const size_t) bytes);
        log_android(ANDROID_LOG_INFO, "%s recv SOCKS5 %s", session, h);
        ng_free(h, __FILE__, __LINE__);

        if (*socks5_status == SOCKS5_HELLO &&
            bytes == 2 && buffer[0] == 5) {
            if (buffer[1] == 0) {
                if (type == SOCK_DGRAM) {
                    *socks5_status = SOCKS5_UDP_ASSOCIATE;
                } else {
                    *socks5_status = SOCKS5_CONNECT;
                }
            }
            else if (buffer[1] == 2)
                *socks5_status = SOCKS5_AUTH;
            else {
                *socks5_status = 0;
                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 auth %d not supported",
                            session, buffer[1]);
                return -1;
            }

        } else if (*socks5_status == SOCKS5_AUTH &&
                   bytes == 2 &&
                   (buffer[0] == 1 || buffer[0] == 5)) {
            if (buffer[1] == 0) {
                if (type == SOCK_DGRAM) {
                    *socks5_status = SOCKS5_UDP_ASSOCIATE;
                } else {
                    *socks5_status = SOCKS5_CONNECT;
                }
                log_android(ANDROID_LOG_WARN, "%s SOCKS5 auth OK", session);
            } else {
                *socks5_status = 0;
                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 auth error %d",
                            session, buffer[1]);
                return -1;
            }

        } else if ((*socks5_status == SOCKS5_CONNECT || *socks5_status == SOCKS5_UDP_ASSOCIATE) &&
                   bytes == 6 + (ipver == 4 ? 4 : 16) &&
                   buffer[0] == 5) {
            if (buffer[1] == 0) {
                if (*socks5_status == SOCKS5_UDP_ASSOCIATE) {
                    *socks5_status = SOCKS5_UDP_ASSOCIATED;
                    log_android(ANDROID_LOG_WARN, "%s SOCKS5 udp associated", session);
                } else {
                    *socks5_status = SOCKS5_CONNECTED;
                    log_android(ANDROID_LOG_WARN, "%s SOCKS5 connected", session);
                }
                if (bind_addr != NULL) {
                    if (ipver == 4) {
                        memcpy(bind_addr, &buffer[4], 4);
                    } else {
                        memcpy(bind_addr, &buffer[4], 16);
                    }
                }
                if (bind_port != NULL) {
                    if (ipver == 4) {
                        memcpy(bind_port, &buffer[4 + 4], 2);
                    } else {
                        memcpy(bind_port, &buffer[4 + 16], 2);
                    }
                }
            } else {
                *socks5_status = 0;
                log_android(ANDROID_LOG_ERROR, "%s SOCKS5 connect error %d",
                            session, buffer[1]);
                return -1;
                /*
                    0x00 = request granted
                    0x01 = general failure
                    0x02 = connection not allowed by ruleset
                    0x03 = network unreachable
                    0x04 = host unreachable
                    0x05 = connection refused by destination host
                    0x06 = TTL expired
                    0x07 = command not supported / protocol error
                    0x08 = address type not supported
                 */
            }

        } else {
            *socks5_status = 0;
            log_android(ANDROID_LOG_ERROR, "%s recv SOCKS5 state %d",
                        session, *socks5_status);
            return -1;
        }
    }
    return 0;
}

int socks5_client_send_cb(int socksfd, uint8_t *socks5_status,
                          int ipver, int type, void *dest_addr, __be16 dest_port,
                          char *session) {
    if (*socks5_status == SOCKS5_HELLO) {
        uint8_t buffer[4] = {5, 2, 0, 2};
        char *h = hex(buffer, sizeof(buffer));
        log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 hello: %s",
                    session, h);
        ng_free(h, __FILE__, __LINE__);
        ssize_t sent = send(socksfd, buffer, sizeof(buffer), MSG_NOSIGNAL);
        if (sent < 0) {
            log_android(ANDROID_LOG_ERROR, "%s send SOCKS5 hello error %d: %s",
                        session, errno, strerror(errno));
            return -1;
        }

    } else if (*socks5_status == SOCKS5_AUTH) {
        uint8_t ulen = strlen(socks5_username);
        uint8_t plen = strlen(socks5_password);
        uint8_t buffer[512];
        *(buffer + 0) = 1; // Version
        *(buffer + 1) = ulen;
        memcpy(buffer + 2, socks5_username, ulen);
        *(buffer + 2 + ulen) = plen;
        memcpy(buffer + 2 + ulen + 1, socks5_password, plen);

        size_t len = 2 + ulen + 1 + plen;

        char *h = hex(buffer, len);
        log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 auth: %s",
                    session, h);
        ng_free(h, __FILE__, __LINE__);
        ssize_t sent = send(socksfd, buffer, len, MSG_NOSIGNAL);
        if (sent < 0) {
            log_android(ANDROID_LOG_ERROR,
                        "%s send SOCKS5 connect error %d: %s",
                        session, errno, strerror(errno));
            return -1;
        }

    } else if (*socks5_status == SOCKS5_CONNECT) {
        uint8_t buffer[22];
        *(buffer + 0) = 5; // version
        *(buffer + 1) = 1; // TCP/IP stream connection
        *(buffer + 2) = 0; // reserved
        *(buffer + 3) = (uint8_t) (ipver == 4 ? 1 : 4);
        if (ipver == 4) {
            memcpy(buffer + 4, dest_addr, 4);
            *((__be16 *) (buffer + 4 + 4)) = dest_port;
        } else {
            memcpy(buffer + 4, dest_addr, 16);
            *((__be16 *) (buffer + 4 + 16)) = dest_port;
        }

        size_t len = (ipver == 4 ? 10 : 22);

        char *h = hex(buffer, len);
        log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 connect: %s",
                    session, h);
        ng_free(h, __FILE__, __LINE__);
        ssize_t sent = send(socksfd, buffer, len, MSG_NOSIGNAL);
        if (sent < 0) {
            log_android(ANDROID_LOG_ERROR,
                        "%s send SOCKS5 connect error %d: %s",
                        session, errno, strerror(errno));
            return -1;
        }

    } else if (*socks5_status == SOCKS5_UDP_ASSOCIATE) {
        uint8_t buffer[22];
        *(buffer + 0) = 5; // version
        *(buffer + 1) = 3; // UDP ASSOCIATE
        *(buffer + 2) = 0; // reserved
        *(buffer + 3) = (uint8_t) (ipver == 4 ? 1 : 4);
        if (ipver == 4) {
            memcpy(buffer + 4, dest_addr, 4);
            *((__be16 *) (buffer + 4 + 4)) = dest_port;
        } else {
            memcpy(buffer + 4, dest_addr, 16);
            *((__be16 *) (buffer + 4 + 16)) = dest_port;
        }

        size_t len = (ipver == 4 ? 10 : 22);

        char *h = hex(buffer, len);
        log_android(ANDROID_LOG_INFO, "%s sending SOCKS5 udp associate: %s",
                    session, h);
        ng_free(h, __FILE__, __LINE__);
        ssize_t sent = send(socksfd, buffer, len, MSG_NOSIGNAL);
        if (sent < 0) {
            log_android(ANDROID_LOG_ERROR,
                        "%s send SOCKS5 udp associate error %d: %s",
                        session, errno, strerror(errno));
            return -1;
        }
    }
    return 0;
}
