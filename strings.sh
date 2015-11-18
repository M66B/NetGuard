#!/bin/bash

grep -RIl "\<string name=\"msg_packages" app/src/main/res | xargs sed -i -e '/msg_packages/d'
grep -RIl "\<string name=\"msg_started" app/src/main/res | xargs sed -i -e '/msg_started/a\
\ \ \ \ <string name="msg_packages">%1$d allowed, %2$d blocked</string>'


#grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
#grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
