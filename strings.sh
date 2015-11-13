#!/bin/bash
#grep -RIl "\<string name=\"msg_try" app/src/main/res | xargs sed -i -e '/msg_try/a \
#\ \ \ \ <string name=\"msg_admin\">Prevent NetGuard from being uninstalled</string>'

grep -RIl "\<string name=\"msg_admin" app/src/main/res | xargs sed -i -e '/msg_admin/d'
#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
