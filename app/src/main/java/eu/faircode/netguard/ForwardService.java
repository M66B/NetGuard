package eu.faircode.netguard;

import android.app.IntentService;
import android.content.Intent;

public class ForwardService extends IntentService {
    private static final String TAG = "NetGuard.Forward";
    private static final String ACTION_START_PORT_FORWARD = "eu.faircode.netguard.START_PORT_FORWARD";
    private static final String ACTION_STOP_PORT_FORWARD = "eu.faircode.netguard.STOP_PORT_FORWARD";

    private native void jni_start_port_forward(int source, int target, int uid);

    private native void jni_stop_port_forward(int source);

    static {
        System.loadLibrary("netguard");
    }

    public ForwardService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        if (ACTION_START_PORT_FORWARD.equals(intent.getAction())) {
            // am startservice -a eu.faircode.netguard.START_PORT_FORWARD --ei source <source> --ei target <target> --ei uid <uid>
            int source = intent.getIntExtra("source", 0);
            int target = intent.getIntExtra("target", 0);
            int uid = intent.getIntExtra("uid", 0);
            jni_start_port_forward(source, target, uid);

        } else if (ACTION_STOP_PORT_FORWARD.equals(intent.getAction())) {
            // am startservice -a eu.faircode.netguard.STOP_PORT_FORWARD --ei source <source>
            int source = intent.getIntExtra("source", 0);
            jni_stop_port_forward(source);
        }
    }
}
