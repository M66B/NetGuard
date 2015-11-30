#!/bin/bash

grep -RIl "\<string name=\"setting_national_roaming" app/src/main/res | xargs sed -i -e '/setting_national_roaming/d'
grep -RIl "\<string name=\"setting_metered" app/src/main/res | xargs sed -i -e '/setting_metered/a\
\ \ <string name="setting_national_roaming">Ignore national roaming</string>'

#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/xxx/yyy/g'
