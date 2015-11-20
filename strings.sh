#!/bin/bash

grep -RIl "\<string name=\"msg_bug" app/src/main/res | xargs sed -i -e '/msg_bug/d'
grep -RIl "\<string name=\"msg_dimming" app/src/main/res | xargs sed -i -e '/msg_dimming/a\
\ \ \ \ <string name="msg_bug">Something has gone wrong, please describe in the next dialog what you were doing to help improve NetGuard</string>'

#grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
#grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
