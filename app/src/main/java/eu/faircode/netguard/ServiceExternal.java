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

import android.app.IntentService;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ServiceExternal extends IntentService {
    private static final String TAG = "NetGuard.External";
    private static final String ACTION_DOWNLOAD_HOSTS_FILE = "eu.faircode.netguard.DOWNLOAD_HOSTS_FILE";

    // am startservice -a eu.faircode.netguard.DOWNLOAD_HOSTS_FILE

    public ServiceExternal() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        if (ACTION_DOWNLOAD_HOSTS_FILE.equals(intent.getAction())) {
            final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

            String hosts_url = prefs.getString("hosts_url", null);
            File tmp = new File(getFilesDir(), "hosts.tmp");
            File hosts = new File(getFilesDir(), "hosts.txt");

            InputStream in = null;
            OutputStream out = null;
            URLConnection connection = null;
            try {
                URL url = new URL(hosts_url);
                connection = url.openConnection();
                connection.connect();

                if (connection instanceof HttpURLConnection) {
                    HttpURLConnection httpConnection = (HttpURLConnection) connection;
                    if (httpConnection.getResponseCode() != HttpURLConnection.HTTP_OK)
                        throw new IOException(httpConnection.getResponseCode() + " " + httpConnection.getResponseMessage());
                }

                int contentLength = connection.getContentLength();
                Log.i(TAG, "Content length=" + contentLength);
                in = connection.getInputStream();
                out = new FileOutputStream(tmp);

                long size = 0;
                byte buffer[] = new byte[4096];
                int bytes;
                while ((bytes = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytes);
                    size += bytes;
                }

                Log.i(TAG, "Downloaded size=" + size);

                if (hosts.exists())
                    hosts.delete();
                tmp.renameTo(hosts);

                String last = SimpleDateFormat.getDateTimeInstance().format(new Date().getTime());
                prefs.edit().putString("hosts_last_download", last).apply();

                ServiceSinkhole.reload("hosts file download", this);

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                if (tmp.exists())
                    tmp.delete();
            } finally {
                try {
                    if (out != null)
                        out.close();
                } catch (IOException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
                try {
                    if (in != null)
                        in.close();
                } catch (IOException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

                if (connection instanceof HttpURLConnection)
                    ((HttpURLConnection) connection).disconnect();
            }
        }
    }
}
