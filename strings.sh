#!/bin/bash

#grep -RIl "\<string name=\"msg_bug" app/src/main/res | xargs sed -i -e '/msg_bug/d'

grep -RIl "\<string name=\"msg_revoked" app/src/main/res | xargs sed -i -e '/msg_revoked/a\
\ \ <string name="msg_installed">%1$s installed</string>'

#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/Default allow Wi-Fi when screen is on/Default allow Wi-Fi when screen on/g'
