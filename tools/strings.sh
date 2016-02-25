#!/bin/bash

grep -RIl "\<string name=\"title_donate" app/src/main/res | xargs sed -i -e '/title_donate/d'
grep -RIl "\<string name=\"msg_voluntary" app/src/main/res | xargs sed -i -e '/msg_voluntary/d'
grep -RIl "\<string name=\"title_thanks" app/src/main/res | xargs sed -i -e '/title_thanks/d'


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
