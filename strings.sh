#!/bin/bash

grep -RIl "\<string name=\"msg_vpn" app/src/main/res | xargs sed -i -e '/msg_vpn/d'
grep -RIl "\<string name=\"msg_completed" app/src/main/res | xargs sed -i -e '/msg_completed/a\
\ \ \ \ <string name=\"msg_vpn\">NetGuard uses a local VPN as a sinkhole to block internet traffic.\
For this reason, please allow a VPN connection in the next dialog.\
Since NetGuard has no internet permission, you know your internet traffic is not being sent anywhere.</string>'

#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
