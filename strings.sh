#!/bin/bash

#grep -RIl "\<string name=\"msg_vpn" app/src/main/res | xargs sed -i -e '/msg_vpn/d'
grep -RIl "\<string name=\"msg_voluntary" app/src/main/res | xargs sed -i -e '/msg_voluntary/a\
\ \ \ \ <string name="msg_dimming">If you cannot press OK in the next dialog, another (screen dimming) application is likely manipulating the screen.</string>'

#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
