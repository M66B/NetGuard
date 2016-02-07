package eu.faircode.netguard;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.PowerManager;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class DownloadTask extends AsyncTask<Object, Integer, Object> {
    private static final String TAG = "NetGuard.Download";

    private Context context;
    private URL url;
    private File file;
    private Listener listener;
    private ProgressDialog progressDialog;
    private PowerManager.WakeLock wakeLock;

    public interface Listener {
        void onCompleted();

        void onCancelled();

        void onException(Throwable ex);
    }

    public DownloadTask(Context context, URL url, File file, Listener listener) {
        this.context = context;
        this.url = url;
        this.file = file;
        this.listener = listener;
    }

    @Override
    protected void onPreExecute() {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, getClass().getName());
        wakeLock.acquire();

        progressDialog = new ProgressDialog(context);
        progressDialog.setIcon(R.mipmap.ic_launcher);
        progressDialog.setTitle(R.string.app_name);
        progressDialog.setMessage(context.getString(R.string.msg_downloading, url.toString()));
        progressDialog.setIndeterminate(true);
        progressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        progressDialog.setCancelable(true);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
            @Override
            public void onCancel(DialogInterface dialog) {
                DownloadTask.this.cancel(true);
            }
        });
        progressDialog.show();
    }

    @Override
    protected Object doInBackground(Object... args) {
        Log.i(TAG, "Downloading " + url + " into " + file);

        InputStream in = null;
        OutputStream out = null;
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK)
                throw new IOException(connection.getResponseCode() + " " + connection.getResponseMessage());

            int contentLength = connection.getContentLength();
            Log.i(TAG, "Content length=" + contentLength);
            in = connection.getInputStream();
            out = new FileOutputStream(file);

            long size = 0;
            byte buffer[] = new byte[4096];
            int bytes;
            while (!isCancelled() && (bytes = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytes);

                size += bytes;
                if (contentLength > 0)
                    publishProgress((int) (size * 100 / contentLength));
            }

            Log.i(TAG, "Downloaded size=" + size);
            return null;
        } catch (Throwable ex) {
            return ex;
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

            if (connection != null)
                connection.disconnect();
        }
    }

    @Override
    protected void onProgressUpdate(Integer... progress) {
        super.onProgressUpdate(progress);
        progressDialog.setIndeterminate(false);
        progressDialog.setMax(100);
        progressDialog.setProgress(progress[0]);
    }

    @Override
    protected void onCancelled() {
        super.onCancelled();
        Log.i(TAG, "Cancelled");
        listener.onCancelled();
    }

    @Override
    protected void onPostExecute(Object result) {
        wakeLock.release();
        progressDialog.dismiss();
        if (result instanceof Throwable) {
            Log.e(TAG, result.toString() + "\n" + Log.getStackTraceString((Throwable) result));
            listener.onException((Throwable) result);
        } else
            listener.onCompleted();
    }
}