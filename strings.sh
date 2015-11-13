#!/bin/bash

#grep -RIl "\<string name=\"msg_vpn" app/src/main/res | xargs sed -i -e '/msg_vpn/d'

grep -RIl "\<string name=\"setting_whitelist_other" app/src/main/res | xargs sed -i -e '/setting_whitelist_other/a\
\ \ \ \ <string name="setting_unused">Default allow when screen is on</string>'

#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
