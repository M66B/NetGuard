#!/bin/bash

grep -RIl "\<string name=\"msg_revoked" app/src/main/res | xargs sed -i -e '/msg_revoked/d'
grep -RIl "\<string name=\"msg_disabled" app/src/main/res | xargs sed -i -e '/msg_disabled/a\
\ \ \ \ <string name="msg_revoked">NetGuard has been disabled, likely by using another VPN based application</string>'

grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
