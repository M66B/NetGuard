#!/bin/bash

grep -RIl "\<string name=\"app_copyright" app/src/main/res | xargs sed -i -e '/app_copyright/a\
\ \ <string name="app_android">NetGuard requires Android 5.0 or later</string>'

#grep -RIl "\<string name=\"msg_bug" app/src/main/res | xargs sed -i -e '/aaa/d'
#grep -RIl "\<string name=\"setting_screen_wifi" app/src/main/res | xargs sed -i -e 's/xxx/yyy/g'
