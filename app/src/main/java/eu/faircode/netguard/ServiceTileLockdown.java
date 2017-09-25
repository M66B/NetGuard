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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/


import android.annotation.TargetApi;
import android.content.SharedPreferences;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.preference.PreferenceManager;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.util.Log;

@TargetApi(Build.VERSION_CODES.N)
public class ServiceTileLockdown extends TileService implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.TileLockdown";

    public void onStartListening() {
        Log.i(TAG, "Start listening");
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.registerOnSharedPreferenceChangeListener(this);
        update();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String key) {
        if ("lockdown".equals(key))
            update();
    }

    private void update() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean lockdown = prefs.getBoolean("lockdown", false);
        Tile tile = getQsTile();
        if (tile != null) {
            tile.setState(lockdown ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
            tile.setIcon(Icon.createWithResource(this, lockdown ? R.drawable.ic_lock_outline_white_24dp : R.drawable.ic_lock_outline_white_24dp_60));
            tile.updateTile();
        }
    }

    public void onStopListening() {
        Log.i(TAG, "Stop listening");
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);
    }

    public void onClick() {
        Log.i(TAG, "Click");

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("lockdown", !prefs.getBoolean("lockdown", false)).apply();
        ServiceSinkhole.reload("tile", this, false);
        WidgetLockdown.updateWidgets(this);
    }
}
