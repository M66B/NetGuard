#!/bin/bash
#grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e '/setting_system/a \
#\ \ \ \ <string name=\"setting_credentials\">Require credentials</string>'
#grep -RIl "\<string name=\"summary_system" app/src/main/res | xargs sed -i -e '/summary_system/a \
#\ \ \ \ <string name=\"summary_credentials\">Prompt to confirm credentials (pin, pattern or password)</string>'

#grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e '/setting_system/d'
grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e 's/Require credentials/Verify credentials/g'
grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e 's/Prompt to confirm credentials (pin, pattern or password)/Confirm pin, pattern, password, etc on opening the application/g'
