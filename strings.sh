#!/bin/bash

grep -RIl "\<string name=\"msg_terms" app/src/main/res | xargs sed -i -e '/msg_terms/d'
grep -RIl "\<string name=\"msg_voluntary" app/src/main/res | xargs sed -i -e '/msg_voluntary/a\
\ \ <string name="msg_terms">By donating you agree to the <a href="http://www.netguard.me/#terms">terms &amp; conditions</a></string>'

#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/xxx/yyy/g'
