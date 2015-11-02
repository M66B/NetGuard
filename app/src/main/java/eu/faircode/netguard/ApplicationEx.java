package eu.faircode.netguard;

import android.app.Application;
import android.util.Log;

public class ApplicationEx extends Application {
    private static final String TAG = "NetGuard.App";

    private Thread.UncaughtExceptionHandler mPrevHandler;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this));

        mPrevHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread thread, Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                if (mPrevHandler != null)
                    mPrevHandler.uncaughtException(thread, ex);
            }
        });
    }
}
