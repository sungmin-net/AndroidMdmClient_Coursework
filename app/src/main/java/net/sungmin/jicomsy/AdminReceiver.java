// ref: https://github.com/googlesamples/android-testdpc/blob/cf9374bc4c7d1a548bbeb8d9bd05828a9d05cd66/app/src/main/java/com/afwsamples/testdpc/DeviceAdminReceiver.java
package net.sungmin.jicomsy;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class AdminReceiver extends DeviceAdminReceiver {

    String LOG_TAG = "JICOMSY_RECEIVER";

    @Override
    public void onProfileProvisioningComplete(Context context, Intent intent) {
        // enable admin
        DevicePolicyManager dpm =
                (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName cn = getComponentName(context);
        dpm.setProfileName(cn, "JICOMSY Device admin");
    }

    public static ComponentName getComponentName(Context context) {
        return new ComponentName(context.getApplicationContext(), AdminReceiver.class);
    }

    @Override
    public void onReceive(Context context, Intent intent) {

        Log.i(LOG_TAG, "onReceive: " + intent.getAction());
        DevicePolicyManager dpm =
                (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        switch (intent.getAction()) {
            case Intent.ACTION_BOOT_COMPLETED:
                if (dpm.isDeviceOwnerApp(context.getPackageName())) {
                    // TODO policy polling
                }
        }
    }
}
