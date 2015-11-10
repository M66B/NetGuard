#!/bin/bash
grep -RIl "\<string name=\"setting_system" app/src/main/res | xargs sed -i -e '/setting_system/a \
\ \ \ \ <string name=\"setting_credentials\">Require credentials</string>'
grep -RIl "\<string name=\"summary_system" app/src/main/res | xargs sed -i -e '/summary_system/a \
\ \ \ \ <string name=\"summary_credentials\">Prompt to confirm credentials (pin, pattern or password)</string>'

#grep -RIl "\<string name=\"title_template_merge" app/src/main/res | xargs sed -i -e 's/Apply template (merge)/Apply template (merge set)/g'

#grep -RIl "\<string name=\"setting_foreground" app/src/main/res | xargs sed -i -e '/setting_foreground/d'
#grep -RIl "\<string name=\"summary_foreground" app/src/main/res | xargs sed -i -e '/summary_foreground/d'
#grep -RIl "\<string name=\"restrict_help_internet" app/src/main/res | xargs sed -i -e 's/internet</Internet</g'
#grep -RIl "\<string name=\"settings_aosp" app/src/main/res | xargs sed -i -e 's/requires restart/requires reboot/g'
