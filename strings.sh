#!/bin/bash

grep -RIl "\<string name=\"msg_bug" app/src/main/res | xargs sed -i -e '/msg_bug/d'

#grep -RIl "\<string name=\"setting_unused" app/src/main/res | xargs sed -i -e '/setting_unused/a\
#\ \ \ \ <string name="setting_screen_other">Default allow mobile when screen is on</string>'
#grep -RIl "\<string name=\"setting_unused" app/src/main/res | xargs sed -i -e '/setting_unused/a\
#\ \ \ \ <string name="setting_screen_wifi">Default allow Wi-Fi when screen is on</string>'
#grep -RIl "\<string name=\"setting_unused" app/src/main/res | xargs sed -i -e '/setting_unused/d'

#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/Default allow Wi-Fi when screen is on/Default allow Wi-Fi when screen on/g'
#grep -RIl "\<string name=\"setting_screen_other" app/src/main/res | xargs sed -i -e 's/Default allow mobile when screen is on/Default allow mobile when screen on/g'
