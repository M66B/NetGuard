package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2016 by Marcel Bokhorst (M66B)
*/

import android.accessibilityservice.AccessibilityService;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;

import java.util.HashMap;
import java.util.Map;

public class Accessibility extends AccessibilityService {
    private String lastActivePackageName = null;
    private Map<ComponentName, Boolean> mapComponentNameActivity = new HashMap<>();

    public static final String ACTION_FOREGROUND_ACTIVITY_CHANGED = "eu.faircode.netguard.ACTION_FOREGROUND_ACTIVITY_CHANGED";
    public static final String EXTRA_PACKAGE_NAME = "Package";

    private static final String TAG = "NetGuard.Accessibility";

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            ComponentName componentName = new ComponentName(
                    event.getPackageName().toString(),
                    event.getClassName().toString()
            );

            synchronized (this) {
                boolean activity = false;
                if (mapComponentNameActivity.containsKey(componentName))
                    activity = mapComponentNameActivity.get(componentName);
                else {
                    try {
                        getPackageManager().getActivityInfo(componentName, 0);
                        activity = true;
                    } catch (PackageManager.NameNotFoundException ignored) {
                    }
                    mapComponentNameActivity.put(componentName, activity);
                }

                Log.i(TAG, componentName + "=" + activity);

                if (activity && (lastActivePackageName == null || !lastActivePackageName.equals((event.getPackageName().toString())))) {
                    lastActivePackageName = event.getPackageName().toString();
                    Log.i(TAG, "Foreground activity=" + lastActivePackageName);

                    Intent intent = new Intent(ACTION_FOREGROUND_ACTIVITY_CHANGED);
                    intent.putExtra(EXTRA_PACKAGE_NAME, lastActivePackageName);
                    LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
                }
            }
        }
    }

    @Override
    public void onInterrupt() {
    }
}