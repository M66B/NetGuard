#!/bin/bash

grep -RIl "\<string name=\"setting_metered" app/src/main/res | xargs sed -i -e '/setting_metered/d'
grep -RIl "\<string name=\"setting_whitelist_roaming" app/src/main/res | xargs sed -i -e '/setting_whitelist_roaming/a\
\ \ \ \ <string name="setting_metered">Handle metered WiFi networks</string>'

grep -RIl "\<string name=\"summary_metered" app/src/main/res | xargs sed -i -e '/summary_metered/d'
grep -RIl "\<string name=\"summary_system" app/src/main/res | xargs sed -i -e '/summary_system/a\
\ \ \ \ <string name="summary_metered">Apply mobile network rules to metered (paid, tethered) WiFi networks</string>'

#grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
#grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
