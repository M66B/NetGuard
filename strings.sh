#!/bin/bash
grep -RIl "\<string name=\"msg_try" app/src/main/res | xargs sed -i -e '/msg_try/a \
\ \ \ \ <string name=\"msg_voluntary\">Donations are completely voluntary and do not unlock any feature. Donations are meant as a way to show your appreciation for the work done.</string>'

#grep -RIl "\<string name=\"msg_admin" app/src/main/res | xargs sed -i -e '/msg_admin/d'
#grep -RIl "\<string name=\"summary_credentials" app/src/main/res | xargs sed -i -e 's/Prevent from being uninstalled/Prevent NetGuard from being uninstalled/g'
