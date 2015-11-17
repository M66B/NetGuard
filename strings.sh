#!/bin/bash

#grep -RIl "\<string name=\"setting_metered" app/src/main/res | xargs sed -i -e '/setting_metered/d'

#grep -RIl "\<string name=\"menu_invite" app/src/main/res | xargs sed -i -e '/menu_invite/a\
#\ \ \ \ <string name="menu_faq">FAQ</string>'

#grep -RIl "\<string name=\"msg_sure" app/src/main/res | xargs sed -i -e '/msg_sure/a\
#\ \ \ \ <string name="msg_faq">Did you check the FAQ?</string>'

grep -RIl "\<string name=\"msg_faq" app/src/main/res | xargs sed -i -e '/msg_faq/a\
\ \ \ \ <string name="msg_no">No</string>'
grep -RIl "\<string name=\"msg_faq" app/src/main/res | xargs sed -i -e '/msg_faq/a\
\ \ \ \ <string name="msg_yes">Yes</string>'

#grep -RIl "\<string name=\"title_disabled" app/src/main/res | xargs sed -i -e 's/Is disabled/is disabled/g'
#grep -RIl "\<string name=\"title_internet" app/src/main/res | xargs sed -i -e 's/Has no internet access/has no internet permission/g'
