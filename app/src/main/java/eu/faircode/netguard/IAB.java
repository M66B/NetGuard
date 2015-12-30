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

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.android.vending.billing.IInAppBillingService;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;

public class IAB implements ServiceConnection {
    private static final String TAG = "Netguard.IAB";

    private Context context;
    private Delegate delegate;
    private IInAppBillingService service = null;

    private static final int IAB_VERSION = 3;
    // adb shell pm clear com.android.vending
    // adb shell am start -n eu.faircode.netguard/eu.faircode.netguard.ActivityMain
    private static final String SKU_PRO = "pro";
    private static final String SKU_DONATE = "donation";
    // private static final String SKU_DONATE = "android.test.purchased";

    public interface Delegate {
        void onReady();
    }

    public IAB(Delegate delegate, Context context) {
        this.context = context;
        this.delegate = delegate;
    }

    public void bind() {
        try {
            Log.i(TAG, "Bind");
            Intent serviceIntent = new Intent("com.android.vending.billing.InAppBillingService.BIND");
            serviceIntent.setPackage("com.android.vending");
            context.bindService(serviceIntent, this, Context.BIND_AUTO_CREATE);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, context);
        }
    }

    public void unbind() {
        if (service != null)
            try {
                Log.i(TAG, "Unbind");
                context.unbindService(this);
                service = null;
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                Util.sendCrashReport(ex, context);
            }
    }

    @Override
    public void onServiceConnected(ComponentName name, IBinder binder) {
        Log.i(TAG, "Connected");
        try {
            service = IInAppBillingService.Stub.asInterface(binder);
            delegate.onReady();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, context);
        }
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {
        Log.i(TAG, "Disconnected");
        service = null;
    }

    public boolean isAvailable(String sku) throws RemoteException, JSONException {
        // Get available SKUs
        ArrayList<String> skuList = new ArrayList<>();
        skuList.add(sku);
        Bundle query = new Bundle();
        query.putStringArrayList("ITEM_ID_LIST", skuList);
        Bundle bundle = service.getSkuDetails(IAB_VERSION, context.getPackageName(), "inapp", query);
        Log.i(TAG, "getSkuDetails");
        Util.logBundle(bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "Response=" + getResult(response));
        if (response != 0)
            throw new IllegalArgumentException(getResult(response));

        // Check available SKUs
        boolean found = false;
        ArrayList<String> details = bundle.getStringArrayList("DETAILS_LIST");
        if (details != null)
            for (String item : details) {
                JSONObject object = new JSONObject(item);
                if (sku.equals(object.getString("productId"))) {
                    found = true;
                    break;
                }
            }
        Log.i(TAG, sku + "=" + found);

        return found;
    }

    public boolean isPurchased(String sku) throws RemoteException {
        // Get purchases
        Bundle bundle = service.getPurchases(IAB_VERSION, context.getPackageName(), "inapp", null);
        Log.i(TAG, "getPurchases");
        Util.logBundle(bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "Response=" + getResult(response));
        if (response != 0)
            throw new IllegalArgumentException(getResult(response));

        // Check purchases
        ArrayList<String> skus = bundle.getStringArrayList("INAPP_PURCHASE_ITEM_LIST");
        return (skus != null && skus.contains(sku));
    }

    public PendingIntent getBuyIntent(String sku) throws RemoteException {
        Bundle bundle = service.getBuyIntent(IAB_VERSION, context.getPackageName(), sku, "inapp", "netguard");
        Log.i(TAG, "getBuyIntent");
        Util.logBundle(bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "Response=" + getResult(response));
        if (response != 0)
            throw new IllegalArgumentException(getResult(response));
        if (!bundle.containsKey("BUY_INTENT"))
            throw new IllegalArgumentException("BUY_INTENT missing");
        return bundle.getParcelable("BUY_INTENT");
    }

    public static String getResult(int responseCode) {
        switch (responseCode) {
            case 0:
                return "OK";
            case 1:
                return "USER_CANCELED";
            case 2:
                return "SERVICE_UNAVAILABLE";
            case 3:
                return "BILLING_UNAVAILABLE";
            case 4:
                return "ITEM_UNAVAILABLE";
            case 5:
                return "DEVELOPER_ERROR";
            case 6:
                return "ERROR";
            case 7:
                return "ITEM_ALREADY_OWNED";
            case 8:
                return "ITEM_NOT_OWNED";
            default:
                return Integer.toString(responseCode);
        }
    }
}
