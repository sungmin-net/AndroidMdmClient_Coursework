package net.sungmin.jicomsy;

import android.Manifest;
import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.text.SimpleDateFormat;
import java.util.Date;

public class MainActivity extends Activity {

    static String LOG_TAG = "JICOMSY_MAIN";
    public static final String ACTIVITY_LOG = "ACTIVITY_LOG";

    DevicePolicyManager mDpm;
    ConnectivityManager mCm;

    TextView mTxtIsDeviceOwner;
    TextView mTxtActivityLogger;
    Button mBtnRemoveAdmin;
    Button mBtnAllowCamera;
    Button mBtnDisallowCamera;
    Button mBtnSendHello;
    Button mBtnStartPolling;
    Button mBtnStopPolling;
    Button mBtnScanWifi;
    Button mBtnClearLog;

    EditText mEtServerIp;
    EditText mEtServerPort;
    String mPackageName;
    ComponentName mComponentName;
    Intent mServiceIntent;

    boolean mIsPolling = false;

    BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Log.d(LOG_TAG, "onReceive() " + action);
            switch(action) {
                case ACTIVITY_LOG:
                    activityLog(intent.getStringExtra(ACTIVITY_LOG));
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + intent.getAction());
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mDpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        mCm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        mPackageName = getApplicationContext().getPackageName();
        mComponentName = AdminReceiver.getComponentName(getApplicationContext());
        mServiceIntent = new Intent(getApplicationContext(), AdminService.class);

        setupButtons();
        enableActivityLog();
    }

    private void enableActivityLog() {
        mTxtActivityLogger = findViewById(R.id.activity_logger);
        mTxtActivityLogger.setMovementMethod(new ScrollingMovementMethod());
        mTxtActivityLogger.setText("[" + getTime() + "] Activity logger started.");
    }

    private void setupButtons() {
        // prepare button and listeners
        mTxtIsDeviceOwner = findViewById(R.id.txt_is_device_owner);
        mBtnRemoveAdmin = findViewById(R.id.btn_remove_admin);
        mBtnRemoveAdmin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(LOG_TAG, "btnRemoveAdminClicked");
                mDpm.clearDeviceOwnerApp(mPackageName);
                activityLog("URAN admin removed.");
                mBtnRemoveAdmin.setEnabled(false);
                mBtnAllowCamera.setEnabled(false);
                mBtnDisallowCamera.setEnabled(false);
            }
        });
        mBtnAllowCamera = findViewById(R.id.btn_allow_camera);
        mBtnAllowCamera.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(LOG_TAG, "btnAllowCameraClicked");
                mDpm.setCameraDisabled(mComponentName, false);
                activityLog("Camera allowed.");
            }
        });
        mBtnDisallowCamera = findViewById(R.id.btn_disallow_camera);
        mBtnDisallowCamera.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.d(LOG_TAG, "btnDisallowCameraClicked");
                mDpm.setCameraDisabled(mComponentName, true);
                activityLog("Camera disallowed.");
            }
        });

        mEtServerIp = findViewById(R.id.et_server_ip);
        mEtServerPort = findViewById(R.id.et_server_port);
        mBtnSendHello = findViewById(R.id.btn_send_hello);
        mBtnSendHello.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {
                Log.i(LOG_TAG, "Send Hello clicked.");
                mServiceIntent.setAction(AdminService.ACTION_SEND_HELLO);
                mServiceIntent.putExtra("SERVER_IP", getServerIp());
                mServiceIntent.putExtra("SERVER_PORT", getServerPort());
                startService(mServiceIntent);
            }
        });

        mBtnScanWifi = findViewById(R.id.btn_scan_wifi);
        mBtnScanWifi.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(LOG_TAG, "Scan wifi clicked.");
                mServiceIntent.setAction(AdminService.ACTION_SCAN_WIFI);
                startService(mServiceIntent);
            }
        });

        mBtnStartPolling = findViewById(R.id.btn_start_polling);
        mBtnStartPolling.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(LOG_TAG, "Start polling clicked.");
                mServiceIntent.setAction(AdminService.ACTION_START_POLLING);
                mServiceIntent.putExtra("SERVER_IP", getServerIp());
                mServiceIntent.putExtra("SERVER_PORT", getServerPort());
                startService(mServiceIntent);
                mBtnStartPolling.setEnabled(false);
                mBtnStopPolling.setEnabled(true);
                mIsPolling = true;
            }
        });

        mBtnStopPolling = findViewById(R.id.btn_stop_polling);
        mBtnStopPolling.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Log.i(LOG_TAG, "Stop polling clicked.");
                mServiceIntent.setAction(AdminService.ACTION_STOP_POLLING);
                stopService(mServiceIntent);
                mBtnStopPolling.setEnabled(false);
                mBtnStartPolling.setEnabled(true);
                mIsPolling = false;
            }
        });

        mBtnClearLog = findViewById(R.id.btn_clear_log);
        mBtnClearLog.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View view) {
                mTxtActivityLogger.setText("[" + getTime() + "] Activity logger cleared.");
            }
        });


    }

//    @Override
//    public void onRequestPermissionsResult(int requestCode, String[] permissions,
//            int[] grantResults) {
//        Log.d(LOG_TAG, "onRequestPermissionsResult()");
//        if (requestCode == 0 && grantResults[0] != PackageManager.PERMISSION_GRANTED) {
//            // TODO - just finish()?
//        }
//    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.d(LOG_TAG, "onResumed");

        Log.d(LOG_TAG, "onResumed" + getApplicationContext().getPackageName());
        boolean isDeviceOwner = mDpm.isDeviceOwnerApp(mPackageName);
        if (isDeviceOwner) {
            mTxtIsDeviceOwner.setText("This app is a device admin!");
            mBtnRemoveAdmin.setEnabled(true);
            mBtnAllowCamera.setEnabled(true);
            mBtnDisallowCamera.setEnabled(true);
        } else {
            mTxtIsDeviceOwner.setText("This app is not a device admin.\n"
                    + "To enable, set below ADB command.\n"
                    + "\"adb shell dpm set-device-owner net.sungmin.jicomsy/.AdminReceiver\"");
            mBtnRemoveAdmin.setEnabled(false);
            mBtnAllowCamera.setEnabled(false);
            mBtnDisallowCamera.setEnabled(false);
        }

        // Check connectivity. Note: This code will not work on Android 10 or higher.
        NetworkInfo activeNetwork = mCm.getActiveNetworkInfo();
        boolean isConnected = activeNetwork != null && activeNetwork.isConnected();

        if (isConnected) {
            mBtnSendHello.setEnabled(true);
            mBtnScanWifi.setEnabled(true);
        } else {
            mBtnSendHello.setEnabled(false);
            mBtnScanWifi.setEnabled(false);
        }

        if (isConnected && isDeviceOwner) {
            if (mIsPolling) {
                mBtnStartPolling.setEnabled(false);
                mBtnStopPolling.setEnabled(true);
            } else {
                mBtnStartPolling.setEnabled(true);
                mBtnStopPolling.setEnabled(false);
            }
        } else {
            mBtnStopPolling.setEnabled(false);
            mBtnStartPolling.setEnabled(false);
        }

        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            Log.d(LOG_TAG, "ACCESS_FINE_LOCATION is not allowed.");
            activityLog("Allow location permission in Settings to scan wifi.");
            mBtnScanWifi.setEnabled(false);
        } else {
            mBtnScanWifi.setEnabled(true);
        }

        registerReceiver(mReceiver, new IntentFilter(ACTIVITY_LOG));
    }

    @Override
    protected void onPause() {
        Log.d(LOG_TAG, "onPause");
        unregisterReceiver(mReceiver);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        Log.d(LOG_TAG, "onDestroy");
        stopService(mServiceIntent);
        super.onDestroy();
    }

    protected String getServerIp() {
        return mEtServerIp.getText().toString();
    }

    protected String getServerPort() {
        return mEtServerPort.getText().toString();
    }

    protected void activityLog(String msg) {
        mTxtActivityLogger.append("\n[" + getTime() + "] " + msg);
    }

    private String getTime() {
        SimpleDateFormat format = new SimpleDateFormat("yy.MM.dd HH:mm:ss");
        return format.format(new Date());
    }

}