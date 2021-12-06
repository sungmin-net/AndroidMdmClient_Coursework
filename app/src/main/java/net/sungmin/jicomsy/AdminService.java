package net.sungmin.jicomsy;

import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.ParcelUuid;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import static net.sungmin.jicomsy.Util.getTimeStamp;

public class AdminService extends Service {

    private static String LOG_TAG = "JICOMSY_SERVICE";
    private static String mUserInstanceId = UUID.randomUUID().toString();
    private static String TEST_PUBLIC_WIFI = "TEST_PUBLIC_WIFI";
    private static String TEST_PUBLIC_BT_NAME = "pBeacon"; // TODO should be more reliable
    private static int NONCE_SIZE_BYTE = 32; // 256 bit
    private static int POLLING_INTERVAL = 3000; // 3 sec
    private static int MAX_VALID_NONCE = 10;
    private static int MAX_VALID_BEACON_TIME = 10000; // 10 sec

    // Actions to communicate with the activity
    static final String ACTION_SEND_HELLO = "action_send_hello";
    static final String ACTION_START_POLLING = "action_start_polling";
    static final String ACTION_STOP_POLLING = "action_stop_polling";
    static final String ACTION_SCAN_WIFI = "action_scan_wifi";
    static final String ACTION_SCAN_BT = "action_scan_bluetooth";

    SSLSocketFactory mSslSocketFactory;
    SSLSocket mSocket;
    boolean mIsPolling = false;
    Thread mNetworkThread;
    JSONObject mCurServerReply;
    List<String> mValidNonces;
    SecureRandom mSecureRandom = new SecureRandom();

    DevicePolicyManager mDpm;
    WifiManager mWm;
    BluetoothManager mBm;
    BluetoothAdapter mBa;
    ComponentName mComponentName;
    BroadcastReceiver mWifiScanReceiver;
    List<ScanResult> mLastWiFiScanResult;
    List<Beacon> mLastBtScanResult;

    BluetoothLeScanner mBleScanner;
    ScanCallback mBleScanCallback;
    Handler mHandler;
    boolean mIsBleScanning;

    // BT wrapper for timestamp
    static class Beacon {
        BluetoothDevice mDevice;
        String mTimeStamp;

        public Beacon(BluetoothDevice device) {
            mDevice = device;
            mTimeStamp = getTimeStamp();
        }
    }

    @Override
    public void onCreate() {
        Log.d(LOG_TAG, "onCreate");

        // prepare ssl context
        try {
            // create keystore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", loadCert());

            // create TrustManager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // create SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            mSslSocketFactory = sslContext.getSocketFactory();

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | KeyManagementException
                | CertificateException e) {
            e.printStackTrace();
        }

        mComponentName = AdminReceiver.getComponentName(getApplicationContext());
        mDpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);

        mWm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        mBm = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        mBa = mBm.getAdapter();
        mHandler = new Handler();

        mWifiScanReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.i(LOG_TAG, "mWifiScanReceiver::onReceive()");
                boolean isSuccess = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false);
                Log.i(LOG_TAG, "mWifiScanReceiver:: isSuccess : " + isSuccess);
                if (isSuccess) {
                    mLastWiFiScanResult = mWm.getScanResults();
                    Log.i(LOG_TAG, "isPublicWifiScanned() : " + isPublicWiFiScanned());
                    activityLog( "isPublicWifiScanned() : " + isPublicWiFiScanned());
                }
            }
        };

        mLastBtScanResult = new ArrayList<>();

        IntentFilter wifiIntentFilter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        getApplicationContext().registerReceiver(mWifiScanReceiver, wifiIntentFilter);

        mBleScanner = BluetoothAdapter.getDefaultAdapter().getBluetoothLeScanner();
        mBleScanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, android.bluetooth.le.ScanResult result) {
                super.onScanResult(callbackType, result);

                Log.i(LOG_TAG, "mBleScanCallback::onScanResult()");

                String name = result.getDevice().getName();
                String addr = result.getDevice().getAddress();
                String uuid = null;
                ParcelUuid[] uuids = result.getDevice().getUuids();
                if (uuids != null && uuids.length != 0) {
                    for (ParcelUuid parcelUuid : uuids) {
                        uuid = parcelUuid.getUuid().toString();
                    }
                }

                Log.i(LOG_TAG, "mBleScanCallback.onScanResult : name(" +
                        result.getDevice().getName() + ") addr(" + result.getDevice().getAddress() +
                        ") uuid(" + uuid + ")");

                activityLog("mBleScanCallback.onScanResult : name(" +
                        result.getDevice().getName() + ") addr(" + result.getDevice().getAddress() +
                        ") uuid(" + uuid + ")");

                mLastBtScanResult.add(new Beacon(result.getDevice()));
            }
        };
    }

    @Override
    public void onDestroy() {
        Log.d(LOG_TAG, "onDestroy() called");
        mIsPolling = false;
        getApplicationContext().unregisterReceiver(mWifiScanReceiver);
        if (mIsBleScanning) {
            stopBleScanning();
        }

        super.onDestroy();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(LOG_TAG, "onStartCommand(): " + intent.getAction());
        String serverIp = intent.getStringExtra("SERVER_IP");
        String serverPortStr = intent.getStringExtra("SERVER_PORT");
        int serverPort = -1;
        if (serverPortStr != null) {
            serverPort = Integer.parseInt(serverPortStr);
        }

        switch (intent.getAction()) {
            case ACTION_SEND_HELLO:
                mIsPolling = false;
                sendToServer(serverIp, serverPort, true /* isEchoUnitTest*/);
                break;

            case ACTION_START_POLLING:
                mIsPolling = true;
                mValidNonces = new ArrayList<>();
                sendToServer(serverIp, serverPort, false /* isEchoUnitTest*/);
                break;

            case ACTION_STOP_POLLING:
                mIsPolling = false;
                if (mIsBleScanning) {
                    stopBleScanning();
                }
                break;

            case ACTION_SCAN_WIFI:
                boolean isWifiScanStarted = mWm.startScan();
                activityLog("isWifiScanStarted : " + isWifiScanStarted);
                break;

            case ACTION_SCAN_BT:
                activityLog("BtScanStarted.");
                // In unit test, stop BLE scanning after 10 sec.
                mHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        activityLog("BtScanStopped.");
                        if (mIsBleScanning) {
                            stopBleScanning();
                        }
                        Log.i(LOG_TAG, "isPublicBluetoothScanned() : " + isPublicBluetoothScanned());
                        activityLog( "isPublicBluetoothScanned() : " + isPublicBluetoothScanned());
                    }
                }, MAX_VALID_BEACON_TIME);

                startBleScanning();
                break;

            default:
                throw new IllegalStateException("Unexpected value: " + intent.getAction());
        }
        return START_NOT_STICKY;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startBleScanning() {
        mIsBleScanning = true;
        mBleScanner.startScan(mBleScanCallback);
    }

    private void stopBleScanning() {
        mIsBleScanning = false;
        mBleScanner.stopScan(mBleScanCallback);
    }

    private boolean isValidSign() {
        boolean ret = false;
        try {
            String servSign = mCurServerReply.getString(Payload.SERVER_SIGN);
            String toBeSigned = mCurServerReply.getString(Payload.TO_BE_SIGNED);
            byte[] signBytes = Base64.decode(servSign, Base64.DEFAULT);

            Signature verifier = Signature.getInstance("SHA256withRSA/PSS",
                    new BouncyCastleProvider());
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    32 , 1));

            verifier.initVerify(loadCert());
            Log.d(LOG_TAG, "isValidSign(), servSignStr : " + servSign);
            Log.d(LOG_TAG, "isValidSign(), toBeSignedStr : " + toBeSigned);
            verifier.update(toBeSigned.getBytes("UTF8"));
            ret = verifier.verify(signBytes);
        } catch (JSONException | NoSuchAlgorithmException | InvalidKeyException | SignatureException
                | UnsupportedEncodingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        Log.d(LOG_TAG, "isValidSignature(), ret : " + ret);
        activityLog("isValidSignature(), ret : " + ret);
        return ret;
    }

    private String getClientPayload(String cmd) {
        JSONObject payload = new JSONObject();
        try {
            payload.put(Payload.MAGIC, "apm_service");

            JSONObject rsaEnc = new JSONObject();
            rsaEnc.put(Payload.VERSION, "0.1");
            rsaEnc.put(Payload.CMD, cmd);
            rsaEnc.put(Payload.USER_ID, mUserInstanceId);
            rsaEnc.put(Payload.NONCE, getNonce());
            payload.put(Payload.RSA_ENC, rsaEncrypt(rsaEnc.toString()));

            payload.put(Payload.SERVER_ALIAS, "UranMdmServer");
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return payload.toString();
    }

    private String getNonce() {
        byte[] newNonce = new byte[ NONCE_SIZE_BYTE ];
        mSecureRandom.nextBytes(newNonce);
        String nonceString = Base64.encodeToString(newNonce, Base64.URL_SAFE);
        mValidNonces.add(nonceString);
        if (mValidNonces.size() == MAX_VALID_NONCE) { // valid nonce lifetime is 20 seconds
            mValidNonces.remove(0); // remove oldest one
        }
        Log.i(LOG_TAG, "getNonce() : " + nonceString);

        return nonceString;
    }

    private String rsaEncrypt(String plainText){
        Log.d(LOG_TAG, "rsaEncrypt(), plainText: " + plainText);
        String cipherText = "rsaEncrypt() failed";
        try {
            Certificate cert = loadCert();
            PublicKey publicKey = cert.getPublicKey();
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            byte[] cipherBytes = cipher.doFinal(plainText.getBytes("UTF8"));
            Log.d(LOG_TAG, "rsaEncrypt(), cipherBytes: " + Arrays.toString(cipherBytes));
            cipherText = Base64.encodeToString(cipherBytes, Base64.NO_WRAP);
            Log.d(LOG_TAG, "rsaEncrypt(), cipherText: " + cipherText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException |
                BadPaddingException | IllegalBlockSizeException | InvalidKeyException |
                InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    private Certificate loadCert() {
        Certificate ret = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream caInput = getResources().openRawResource(R.raw.mdm_server);
            ret = cf.generateCertificate(caInput);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return ret;
    }

    private void activityLog(String msg) {
        Intent intent = new Intent(MainActivity.ACTIVITY_LOG);
        intent.putExtra(MainActivity.ACTIVITY_LOG, msg);
        sendBroadcast(intent);
    }

    private void sendToServer(String servIp, int servPort, boolean isEchoUnitTest) {
        if (mNetworkThread != null && mNetworkThread.isAlive()) {
            Log.d(LOG_TAG, "Current network thread is interrupted.");
            mNetworkThread.interrupt();
        }

        mNetworkThread = new Thread(new Runnable() {
            @Override
            public void run() {
                do {
                    Log.d(LOG_TAG, "Network thread is living! isEchoUnitTest: " + isEchoUnitTest +
                            ", mIsPolling: " + mIsPolling);

                    String msg = null;
                    if (isEchoUnitTest) {
                        msg = "Hello! I am Android device.";
                    } else {
                        msg = getClientPayload(Payload.CLIENT_REQUEST_POLICIES);

                        // trigger wifi scan
                        boolean isWifiScanStarted = mWm.startScan();
                        activityLog("isWifiScanStarted : " + isWifiScanStarted);

                        // trigger bt scan
                        if (!mIsBleScanning) {
                            mIsBleScanning = true;
                            mBleScanner.startScan(mBleScanCallback);
                        }
                        activityLog("isBtScanStarted : " + mIsBleScanning);
                    }

                    try {
                        if (mSocket == null || mSocket.isClosed()) {
                            mSocket = (SSLSocket) mSslSocketFactory.createSocket(servIp, servPort);
                            mSocket.setEnabledProtocols(mSocket.getEnabledProtocols());
                            mSocket.setEnabledCipherSuites(mSocket.getSupportedCipherSuites());
                        }

                        BufferedReader reader = new BufferedReader(
                                new InputStreamReader(mSocket.getInputStream()));

                        BufferedWriter bw = new BufferedWriter(
                                new OutputStreamWriter(mSocket.getOutputStream()));
                        PrintWriter writer = new PrintWriter(bw, true /*auto flush*/);

                        writer.println(msg);
                        Log.d(LOG_TAG, "Device sent \"" + msg + "\"");
                        activityLog("Device sent \"" + msg + "\"");

                        String reply = reader.readLine();
                        activityLog("Device received \"" + reply + "\"");
                        Log.d(LOG_TAG, "Device received \"" + reply + "\"");
                        parseServerMsg(reply);

                        if (!isEchoUnitTest && isValidSign() && isValidNonce()
                                && isPublicArea()) {
                            applyPolicies();
                        } else {
                            releasePolicies();
                        }
                        
                        if (!isEchoUnitTest) {
                            Thread.sleep(POLLING_INTERVAL);
                        }
                    } catch (IOException | InterruptedException e) {
                        e.printStackTrace();
                    } finally {
                        if (mSocket != null && !mSocket.isClosed()) {
                            try {
                                mSocket.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                } while (!isEchoUnitTest && mIsPolling);
            }
        });

        mNetworkThread.start();
    }

    private boolean isValidNonce() {
        boolean result = false;
        try {
            String servNonce = mCurServerReply.getJSONObject(Payload.TO_BE_SIGNED)
                    .getString(Payload.NONCE);
            result = mValidNonces.contains(servNonce);

            Log.d(LOG_TAG, "received servNonce :" + servNonce);
            Log.d(LOG_TAG, "current valid nonces : " + mValidNonces.toString());

        } catch (JSONException e) {
            e.printStackTrace();
        }
        Log.d(LOG_TAG, "isValidNonce(), result : " + result);
        activityLog("isValidNonce() : " + result);
        return result;
    }

    private boolean isValidTimeStamp(String timeStampStr) {
        boolean ret = false;
        try {
            SimpleDateFormat format = new SimpleDateFormat(Util.TIME_STAMP_FORMAT);
            Date loggedTime = format.parse(timeStampStr);
            Date curTime = new Date();
            ret = (curTime.getTime() - loggedTime.getTime()) < MAX_VALID_BEACON_TIME;
            Log.d(LOG_TAG, "curTime : " + curTime.getTime() + ", timeStamp: " +
                    loggedTime.getTime());
        } catch (ParseException e) {
            e.printStackTrace();
        }
        Log.d(LOG_TAG, "isValidTimeStamp() : " + ret);
        return ret;
    }

    private void applyPolicies() {
        try {
            // get policy content
            JSONObject policies = mCurServerReply.getJSONObject(Payload.TO_BE_SIGNED)
                    .getJSONObject(Payload.SERVER_REPLY_POLICIES);
            
            boolean isCameraAllowed = policies.getBoolean(Payload.POLICY_ALLOW_CAMERA);
            Log.d(LOG_TAG, "applyPolicies(), isCameraAllowed : " + isCameraAllowed);

            mDpm.setCameraDisabled(mComponentName, !isCameraAllowed);
            activityLog("Allow camera : " + isCameraAllowed);

        } catch (JSONException e) {
            e.printStackTrace();
        }
    }
    
    private void releasePolicies() {
        // NOTE. If the device is out of public area, mdm policy should be released
        if (mDpm.getCameraDisabled(mComponentName)) {
            mDpm.setCameraDisabled(mComponentName, false); // release disable camera policy
        }
    }

    private boolean isPublicArea() {
        boolean result = isPublicWiFiScanned() || isPublicBluetoothScanned()
                || isPublicIndoorLocalized();
        Log.d(LOG_TAG, "isPublicArea(), result : " + result);
        activityLog("isPublicArea(), result : " + result);
        return result;
    }

    private boolean isPublicWiFiScanned() {
        boolean result = false;
        for(ScanResult wifi : mLastWiFiScanResult) {
            if (TEST_PUBLIC_WIFI.equals(wifi.SSID)) {
                result = true;
                break;
            }
        }
        Log.d(LOG_TAG, "isPublicWiFiScanned(), result : " + result);
        activityLog("isPublicWiFiScanned(), result : " + result);
        return result;
    }

    private boolean isPublicBluetoothScanned() {
        boolean result = false;

        // Remove outdated data first
        List<Beacon> toBeRemoved = new ArrayList<>();
        for (int i = 0 ; i < mLastBtScanResult.size() ; i++) {
            Beacon cur = mLastBtScanResult.get(i);
            if (!isValidTimeStamp(cur.mTimeStamp)) {
                toBeRemoved.add(cur);
            }
        }

        for (Beacon b : toBeRemoved) {
            mLastBtScanResult.remove(b);
        }

        for (int i = 0 ; i < mLastBtScanResult.size() ; i++) {
            String name = mLastBtScanResult.get(i).mDevice.getName();
            if (name != null && name.startsWith(TEST_PUBLIC_BT_NAME)) {
                result = true;
                break;
            }
        }

        Log.d(LOG_TAG, "isPublicBluetoothScanned(), result : " + result);
        activityLog("isPublicBluetoothScanned(), result : " + result);
        return result;
    }

    private boolean isPublicIndoorLocalized() {
        // TODO
        boolean result = false;
        Log.d(LOG_TAG, "isPublicIndoorLocalized(), result : " + result);
        activityLog("isPublicIndoorLocalized(), result : " + result);
        return result;
    }

    private void parseServerMsg(String reply) {
        try {
            mCurServerReply = new JSONObject(reply);
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }
}
