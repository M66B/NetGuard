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

    Copyright 2015 by Marcel Bokhorst (M66B)
*/

import android.content.Intent;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceFragment;

public class FragmentSettings extends PreferenceFragment {
    private static final Intent INTENT_VPN_SETTINGS = new Intent("android.net.vpn.SETTINGS");

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        addPreferencesFromResource(R.xml.preferences);

        Preference pref_export = getPreferenceScreen().findPreference("export");
        pref_export.setEnabled(getIntentCreateDocument().resolveActivity(getActivity().getPackageManager()) != null);
        pref_export.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                getActivity().startActivityForResult(getIntentCreateDocument(), ActivitySettings.REQUEST_EXPORT);
                return true;
            }
        });

        Preference pref_import = getPreferenceScreen().findPreference("import");
        pref_import.setEnabled(getIntentCreateDocument().resolveActivity(getActivity().getPackageManager()) != null);
        pref_import.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                getActivity().startActivityForResult(getIntentOpenDocument(), ActivitySettings.REQUEST_IMPORT);
                return true;
            }
        });

        Preference pref_vpn = getPreferenceScreen().findPreference("vpn");
        pref_vpn.setEnabled(INTENT_VPN_SETTINGS.resolveActivity(getActivity().getPackageManager()) != null);
        pref_vpn.setIntent(INTENT_VPN_SETTINGS);
    }


    private static Intent getIntentCreateDocument() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/xml");
        intent.putExtra(Intent.EXTRA_TITLE, "netguard.xml");
        return intent;
    }

    private static Intent getIntentOpenDocument() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/xml");
        return intent;
    }
}
