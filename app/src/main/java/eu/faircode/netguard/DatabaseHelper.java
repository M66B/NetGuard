package eu.faircode.netguard;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;


import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = "NetGuard.Database";

    private static final String DB_NAME = "Netguard";
    private static final int DB_VERSION = 1;

    private static List<LogChangedListener> logChangedListeners = new ArrayList<LogChangedListener>();

    private Context mContext;

    public DatabaseHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        mContext = context;
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.i(TAG, "Creating database " + DB_NAME + ":" + DB_VERSION);
        createTableLog(db);
    }

    private void createTableLog(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE log (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", ip TEXT" +
                ");");
        db.execSQL("CREATE INDEX idx_log_time ON log(time)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.i(TAG, "Upgrading from version " + oldVersion + " to " + newVersion);

        db.beginTransaction();
        try {
            db.setVersion(DB_VERSION);

            db.setTransactionSuccessful();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            db.endTransaction();
        }
    }

    // Location

    public DatabaseHelper insertLog(String ip) {
        synchronized (mContext.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("time", new Date().getTime());
            cv.put("ip", ip);

            if (db.insert("log", null, cv) == -1)
                Log.e(TAG, "Insert log failed");
        }

        for (LogChangedListener listener : logChangedListeners)
            try {
                listener.onAdded();
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        return this;
    }

    public Cursor getLog() {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, * FROM log";
        query += " ORDER BY time DESC";
        return db.rawQuery(query, new String[]{});
    }

    public static void addLogChangedListener(LogChangedListener listener) {
        logChangedListeners.add(listener);
    }

    public static void removeLocationChangedListener(LogChangedListener listener) {
        logChangedListeners.remove(listener);
    }

    public interface LogChangedListener {
        void onAdded();
    }
}
