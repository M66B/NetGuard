#!/bin/bash

#grep -RIl "\<string name=\"msg_vpn" app/src/main/res | xargs sed -i -e '/msg_vpn/d'

grep -RIl "\<string name=\"title_roaming" app/src/main/res | xargs sed -i -e '/title_roaming/a\
\ \ \ \ <string name="title_internet">Has no internet access</string>'
grep -RIl "\<string name=\"title_roaming" app/src/main/res | xargs sed -i -e '/title_roaming/a\
\ \ \ \ <string name="title_disabled">Is disabled</string>'

#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
