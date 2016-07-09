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

import android.annotation.TargetApi;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.PersistableBundle;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ServiceJob extends JobService {
    private static int id = 0;
    private static final String TAG = "NetGuard.Job";

    private static final String cUrl = "https://crowd.netguard.me/";
    private static final int cTimeOutMs = 15000;

    @Override
    public boolean onStartJob(JobParameters params) {
        Log.i(TAG, "Execute job=" + params.getJobId());

        new AsyncTask<JobParameters, Object, Object>() {

            @Override
            protected JobParameters doInBackground(JobParameters... params) {
                Log.i(TAG, "Start job=" + params[0].getJobId());

                HttpsURLConnection urlConnection = null;
                try {
                    String android_id = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
                    JSONObject json = new JSONObject();
                    json.put("device", Util.sha256(android_id, ""));
                    json.put("sdk", Build.VERSION.SDK_INT);
                    json.put("netguard", Util.getSelfVersionCode(ServiceJob.this));
                    json.put("store", getPackageManager().getInstallerPackageName(getPackageName()));

                    for (String name : params[0].getExtras().keySet())
                        json.put(name, params[0].getExtras().get(name));

                    urlConnection = (HttpsURLConnection) new URL(cUrl).openConnection();
                    urlConnection.setConnectTimeout(cTimeOutMs);
                    urlConnection.setReadTimeout(cTimeOutMs);
                    urlConnection.setRequestProperty("Accept", "application/json");
                    urlConnection.setRequestProperty("Content-type", "application/json");
                    urlConnection.setRequestMethod("POST");
                    urlConnection.setDoInput(true);
                    urlConnection.setDoOutput(true);

                    OutputStream out = new BufferedOutputStream(urlConnection.getOutputStream());
                    out.write(json.toString().getBytes()); // UTF-8
                    out.flush();

                    int code = urlConnection.getResponseCode();
                    if (code != HttpsURLConnection.HTTP_OK)
                        throw new IOException("HTTP " + code);

                    InputStreamReader isr = new InputStreamReader(urlConnection.getInputStream());
                    String response = read(isr);
                    Log.i(TAG, "Response=" + response);

                    jobFinished(params[0], false);
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    jobFinished(params[0], true);
                } finally {
                    if (urlConnection != null)
                        urlConnection.disconnect();
                }

                return null;
            }
        }.execute(params);

        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Log.i(TAG, "Start job=" + params.getJobId());
        return true;
    }

    private String read(InputStreamReader reader) {
        StringBuilder sb = new StringBuilder(2048);
        char[] read = new char[128];
        try {
            for (int i; (i = reader.read(read)) >= 0; sb.append(read, 0, i)) ;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        return sb.toString();
    }

    public static boolean can(boolean submit, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        return ((!submit || prefs.getBoolean("submit", true)) && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP);
    }

    public static void submit(Rule rule, Context context) {
        PersistableBundle bundle = new PersistableBundle();
        bundle.putString("type", "rule");

        bundle.putInt("wifi_default", rule.wifi_default ? 1 : 0);
        bundle.putInt("other_default", rule.other_default ? 1 : 0);
        bundle.putInt("screen_wifi_default", rule.screen_wifi_default ? 1 : 0);
        bundle.putInt("screen_other_default", rule.screen_other_default ? 1 : 0);
        bundle.putInt("roaming_default", rule.roaming_default ? 1 : 0);

        bundle.putInt("wifi_blocked", rule.wifi_blocked ? 1 : 0);
        bundle.putInt("other_blocked", rule.other_blocked ? 1 : 0);
        bundle.putInt("screen_wifi", rule.screen_wifi ? 1 : 0);
        bundle.putInt("screen_other", rule.screen_other ? 1 : 0);
        bundle.putInt("roaming", rule.roaming ? 1 : 0);

        bundle.putInt("apply", rule.apply ? 1 : 0);
        bundle.putInt("notify", rule.notify ? 1 : 0);

        submit(rule, bundle, context);
    }

    public static void submit(Rule rule, int version, int protocol, String daddr, int dport, int blocked, Context context) {
        PersistableBundle bundle = new PersistableBundle();
        bundle.putString("type", "host");

        bundle.putInt("version", version);
        bundle.putInt("protocol", protocol);
        bundle.putString("daddr", daddr);
        bundle.putInt("dport", dport);
        bundle.putInt("blocked", blocked);

        submit(rule, bundle, context);
    }

    private static void submit(Rule rule, PersistableBundle bundle, Context context) {
        PackageManager pm = context.getPackageManager();
        JobScheduler scheduler = (JobScheduler) context.getSystemService(Context.JOB_SCHEDULER_SERVICE);

        // Add application data
        bundle.putString("package", rule.info.packageName);
        bundle.putInt("version_code", rule.info.versionCode);
        bundle.putString("version_name", rule.info.versionName);
        bundle.putString("label", rule.info.applicationInfo.loadLabel(pm).toString());
        bundle.putInt("system", rule.system ? 1 : 0);
        bundle.putString("installer", pm.getInstallerPackageName(rule.info.packageName));

        // Cancel overlapping jobs
        for (JobInfo pending : scheduler.getAllPendingJobs()) {
            String type = pending.getExtras().getString("type");
            if (type != null && type.equals(bundle.getString("type"))) {
                if (type.equals("rule")) {
                    String pkg = pending.getExtras().getString("package");
                    if (pkg != null && pkg.equals(bundle.getString("package"))) {
                        Log.i(TAG, "Canceling id=" + pending.getId());
                        scheduler.cancel(pending.getId());
                    }
                } else if (type.equals("host")) {
                    String pkg = pending.getExtras().getString("package");
                    int version = pending.getExtras().getInt("version");
                    int protocol = pending.getExtras().getInt("protocol");
                    String daddr = pending.getExtras().getString("daddr");
                    int dport = pending.getExtras().getInt("dport");
                    if (pkg != null && pkg.equals(bundle.getString("package")) &&
                            version == bundle.getInt("version") &&
                            protocol == bundle.getInt("protocol") &&
                            daddr != null && daddr.equals(bundle.getString("daddr")) &&
                            dport == bundle.getInt("dport")) {
                        Log.i(TAG, "Canceling id=" + pending.getId());
                        scheduler.cancel(pending.getId());
                    }
                }
            }
        }

        // Schedule job
        ComponentName serviceName = new ComponentName(context, ServiceJob.class);
        JobInfo job = new JobInfo.Builder(++id, serviceName)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
                .setMinimumLatency(15 * 1000)
                .setExtras(bundle)
                .setPersisted(true)
                .build();
        scheduler.schedule(job);

        Log.i(TAG, "Scheduled job=" + job.getId());
    }
}
