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

    Copyright 2015-2024 by Marcel Bokhorst (M66B)
*/

#include "netguard.h"

int get_sni(
        const uint8_t *data,
        const uint16_t datalen,
        char *server_name) {
    if (datalen < 6) {
        log_android(ANDROID_LOG_DEBUG, "TLS header too short");
        return 0;
    }

    uint8_t content_type = (uint8_t) data[0];
    uint8_t major_version = (uint8_t) data[1];
    uint8_t minor_version = (uint8_t) data[2];
    uint16_t content_length = ((uint16_t) data[3] << 8) | data[4];
    uint8_t message_type = (uint8_t) data[5];

    // https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
    if (content_type != TLS_HANDSHAKE_RECORD ||
        major_version < 0x03 ||
        5 + content_length != datalen ||
        message_type != TLS_MESSAGE_CLIENTHELLO) {
        log_android(ANDROID_LOG_DEBUG, "TLS content %d version %d length %d/%d type %d",
                    content_type, major_version, 5 + content_length, datalen, message_type);
        return 0;
    }

    log_android(ANDROID_LOG_DEBUG, "TLS client hello version %d.%d",
                major_version, minor_version);

    uint8_t index = 6 + // header above
                    3 + // client hello length
                    2 + // client hello protocol version
                    32; // random value

    // Session ID
    if (index >= datalen) {
        log_android(ANDROID_LOG_WARN, "TLS session ID %d/%d", index, datalen);
        return 0;
    }

    log_android(ANDROID_LOG_DEBUG, "TLS hello version %d.%d",
                data[9], data[10]);

    uint8_t session_len = data[index];
    index += 1 + session_len;

    // Cipher suites
    if (index + 1 >= datalen) {
        log_android(ANDROID_LOG_WARN, "TLS cipher suites %d/%d", index + 1, datalen);
        return 0;
    }
    uint16_t suites_len = ((uint16_t) data[index] << 8) | data[index + 1];
    index += 2 + suites_len;

    // Compression method
    if (index >= datalen) {
        log_android(ANDROID_LOG_WARN, "TLS compression %d/%d", index, datalen);
        return 0;
    }
    uint8_t compression_len = data[index];
    index += 1 + compression_len;

    // Extensions length
    if (index + 1 >= datalen) {
        log_android(ANDROID_LOG_WARN, "TLS extensions %d/%d", index + 1, datalen);
        return 0;
    }
    uint16_t edatalen = ((uint16_t) data[index] << 8) | data[index + 1];
    index += 2;

    if (edatalen == 0 || index + edatalen != datalen) {
        log_android(ANDROID_LOG_WARN, "TLS extensions(2) len=%d %d/%d",
                    edatalen, index + edatalen, datalen);
        return 0;
    }

    uint16_t eindex = 0;
    const uint8_t *edata = data + index;
    while (eindex < edatalen) {
        if (eindex + 1 >= edatalen) {
            log_android(ANDROID_LOG_WARN, "TLS ext_type %d/%d", eindex + 1, edatalen);
            return 0;
        }
        uint16_t ext_type = ((uint16_t) edata[eindex] << 8) | edata[eindex + 1];
        eindex += 2;
        log_android(ANDROID_LOG_DEBUG, "TLS ext_type=%d", ext_type);

        if (eindex + 1 >= edatalen) {
            log_android(ANDROID_LOG_WARN, "TLS ext_len %d/%d", eindex + 1, edatalen);
            return 0;
        }
        uint16_t ext_len = ((uint16_t) edata[eindex] << 8) | edata[eindex + 1];
        eindex += 2;

        if (eindex + ext_len > edatalen) {
            log_android(ANDROID_LOG_WARN, "TLS ext_len(2) %d/%d", eindex + ext_len, edatalen);
            return 0;
        }

        // https://datatracker.ietf.org/doc/html/rfc6066
        if (ext_type == TLS_EXTENSION_TYPE_SERVER_NAME) {
            if (eindex + 1 >= edatalen) {
                log_android(ANDROID_LOG_WARN, "TLS sni_len %d/%d", eindex + 1, edatalen);
                return 0;
            }
            uint16_t sni_len = ((uint16_t) edata[eindex] << 8) | edata[eindex + 1];
            eindex += 2;
            log_android(ANDROID_LOG_DEBUG, "TLS sni_len=%d", sni_len);


            if (eindex + sni_len >= edatalen) {
                log_android(ANDROID_LOG_WARN, "TLS sni_len(2) len=%d %d/%d",
                            sni_len, eindex + sni_len, edatalen);
                return 0;
            }

            if (eindex >= edatalen) {
                log_android(ANDROID_LOG_WARN, "TLS sni_type %d/%d", eindex, edatalen);
                return 0;
            }
            uint8_t sni_type = edata[eindex++];
            if (sni_type != 0) {
                log_android(ANDROID_LOG_WARN, "TLS sni_type=%d", sni_type);
                return 0;
            }

            if (eindex + 1 >= edatalen) {
                log_android(ANDROID_LOG_WARN, "TLS name_len %d/%d", eindex + 1, edatalen);
                return 0;
            }
            uint16_t name_len = ((uint16_t) edata[eindex] << 8) | edata[eindex + 1];
            eindex += 2;

            if (eindex + name_len >= edatalen) {
                log_android(ANDROID_LOG_WARN, "TLS name_len(2) len=%d %d/%d",
                            name_len, eindex + name_len, edatalen);
                return 0;
            }
            if (name_len >= TLS_SNI_LENGTH) {
                log_android(ANDROID_LOG_WARN, "TLS name_len(3) %d/%d",
                            name_len, TLS_SNI_LENGTH);
                return 0;
            }

            memcpy(server_name, edata + eindex, name_len);
            server_name[name_len] = 0;

            return 1;
        }

        eindex += ext_len;
    }

    return 0;
}
