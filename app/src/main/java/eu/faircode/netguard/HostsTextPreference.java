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

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.AttributeSet;
import android.util.Patterns;
import android.widget.Button;

public class HostsTextPreference extends EditTextPreference {

    private HostsTextPreferenceWatcher mTextWatcher = new HostsTextPreferenceWatcher();

    public HostsTextPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public HostsTextPreference(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    protected void onEditTextChanged() {
        Dialog dlg = getDialog();
        if(dlg instanceof AlertDialog) {
            AlertDialog alertDlg = (AlertDialog)dlg;
            Button btn = alertDlg.getButton(AlertDialog.BUTTON_POSITIVE);
            boolean enable = Patterns.WEB_URL.matcher(getEditText().getText().toString()).matches();
            btn.setEnabled(enable);
            if(!enable) {
                this.getEditText().setError("Invalid URL");
            }
        }
    }

    private class HostsTextPreferenceWatcher implements TextWatcher {
        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count){}

        @Override
        public void beforeTextChanged(CharSequence s, int start, int before, int count){}

        @Override
        public void afterTextChanged(Editable s)
        {
            onEditTextChanged();
        }
    }

    @Override
    protected void showDialog(Bundle state) {
        super.showDialog(state);
        getEditText().removeTextChangedListener(mTextWatcher);
        getEditText().addTextChangedListener(mTextWatcher);
        onEditTextChanged();
    }
}
