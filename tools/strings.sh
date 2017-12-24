#!/bin/bash

grep -RIl "\<string name=\"app_copyright" app/src/main/res | xargs sed -i -e 's/-2017/–2018/g'
grep -RIl "\<string name=\"app_copyright" app/src/main/res | xargs sed -i -e 's/–2017/–2018/g'


#grep -RIl "\<string name=\"setting_import" app/src/main/res | xargs sed -i -e '/setting_import/a\
#\ \ <string name="setting_backup">Backup</string>'
#grep -RIl "\<string name=\"setting_import" app/src/main/res | xargs sed -i -e '/setting_import/a\
#\ \ <string name="setting_options">Options</string>'
#grep -RIl "\<string name=\"setting_import" app/src/main/res | xargs sed -i -e '/setting_import/a\
#\ \ <string name="setting_defaults">Defaults</string>'

#grep -RIl "\<string name=\"summary_national_roaming" app/src/main/res | xargs sed -i -e '/summary_national_roaming/d'
#grep -RIl "\<string name=\"summary_metered" app/src/main/res | xargs sed -i -e '/summary_metered/a\
#\ \ <string name="summary_national_roaming">Do not apply the roaming rules when the SIM and mobile network country are the same</string>'

#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/xxx/yyy/g'
