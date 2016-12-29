#!/bin/bash
. tools/config.sh

#https://github.com/mendhak/Crowdin-Android-Importer

rm -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-iw/
rm -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rBH/
rm -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rEG/
rm -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rSA/
rm -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rYE/

python $importer_dir/crowdin.py --p=app/src/main -a=get -i netguard -k $api_key

mkdir -p /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-iw/
mkdir -p /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rBH/
mkdir -p /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rEG/
mkdir -p /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rSA/
mkdir -p /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rYE/

cp -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-he/* \
	/home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-iw/

cp -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar/* \
	/home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rBH/

cp -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar/* \
	/home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rEG/

cp -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar/* \
	/home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rSA/

cp -R /home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar/* \
	/home/marcel/Documents/android/projects/NetGuard/app/src/main/res/values-ar-rYE/

sed -i s/-2016/–2017/ app/src/main/res/values*/strings.xml
