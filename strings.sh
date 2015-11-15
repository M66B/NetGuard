#!/bin/bash

grep -RIl "\<string name=\"setting_vpn" app/src/main/res | xargs sed -i -e '/setting_vpn/d'
grep -RIl "\<string name=\"setting_import" app/src/main/res | xargs sed -i -e '/setting_import/a\
\ \ \ \ <string name="setting_technical">Technical information</string>'

#grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
#grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
