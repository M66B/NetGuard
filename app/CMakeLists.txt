
cmake_minimum_required(VERSION 3.4.1)

add_library( netguard
             SHARED
             src/main/jni/netguard/netguard.c
             src/main/jni/netguard/session.c
             src/main/jni/netguard/ip.c
             src/main/jni/netguard/tcp.c
             src/main/jni/netguard/udp.c
             src/main/jni/netguard/icmp.c
             src/main/jni/netguard/dns.c
             src/main/jni/netguard/dhcp.c
             src/main/jni/netguard/pcap.c
             src/main/jni/netguard/util.c )

include_directories( src/main/jni/netguard/ )

find_library( log-lib
              log )

target_link_libraries( netguard
                       ${log-lib} )
