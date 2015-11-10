#!/bin/bash
#grep -RIl "\<string name=\"msg_try" app/src/main/res | xargs sed -i -e '/msg_try/a \
#\ \ \ \ <string name=\"msg_admin\">Prevent NetGuard from being uninstalled</string>'

#grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e '/setting_system/d'
grep -RIl "\<string name=\"msg_admin" app/src/main/res | xargs sed -i -e 's/Prevent NetGuard from being uninstalled/Prevent from being uninstalled/g'
