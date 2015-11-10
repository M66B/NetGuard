#!/bin/bash
#grep -RIl "\<string name=\"msg_settings_specific" app/src/main/res | xargs sed -i -e '/msg_settings_specific/a \
#\ \ \ \ <string name=\"msg_corrupt\">The privacy database was reset, because it was corrupt</string>'

#grep -RIl "\<string name=\"title_template_merge" app/src/main/res | xargs sed -i -e 's/Apply template (merge)/Apply template (merge set)/g'

grep -RIl "\<string name=\"setting_foreground" app/src/main/res | xargs sed -i -e '/setting_foreground/d'
grep -RIl "\<string name=\"summary_foreground" app/src/main/res | xargs sed -i -e '/summary_foreground/d'
#grep -RIl "\<string name=\"restrict_help_internet" app/src/main/res | xargs sed -i -e 's/internet</Internet</g'
#grep -RIl "\<string name=\"settings_aosp" app/src/main/res | xargs sed -i -e 's/requires restart/requires reboot/g'
