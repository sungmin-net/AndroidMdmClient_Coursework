package net.sungmin.jicomsy;

import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
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

public class AdminService extends Service {

    private static String LOG_TAG = "JICOMSY_SERVICE";
    private static String mUserInstanceId = UUID.randomUUID().toString();
    private static String TEST_PUBLIC_WIFI = "TEST_PUBLIC_WIFI";

    // Actions to communicate with apllication activity
    static final String ACTION_SEND_HELLO = "action_send_hello";
    static final String ACTION_START_POLLING = "action_start_polling";
    static final String ACTION_STOP_POLLING = "action_stop_polling";
    static final String ACTION_SCAN_WIFI = "action_scan_wifi";

    SSLSocketFactory mSslSocketFactory;
    SSLSocket mSocket;
    boolean mFlagNetworkStop = false;
    Thread mNetworkThread;
    JSONObject mCurServerReply;

    DevicePolicyManager mDpm;
    WifiManager mWm;
    ComponentName mComponentName;
    BroadcastReceiver mWifiScanReceiver;
    List<ScanResult> mLastWiFiScanResult;

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
        mWifiScanReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.i(LOG_TAG, "mWifiScanReceiver::onReceive()");
                boolean isSuccess = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false);
                Log.i(LOG_TAG, "mWifiScanReceiver:: isSuccess : " + isSuccess);
                if (isSuccess) {
                    mLastWiFiScanResult = mWm.getScanResults();
                    Log.i(LOG_TAG, "mWifiScanReceiver::mLastWiFiScanResult.size() : "
                            + mLastWiFiScanResult.size());
                    activityLog("Update AP lists");
                    for (ScanResult s : mLastWiFiScanResult) {
                        activityLog(s.SSID);
                    }
                }
            }
        };

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        getApplicationContext().registerReceiver(mWifiScanReceiver, intentFilter);
    }

    @Override
    public void onDestroy() {
        Log.d(LOG_TAG, "onDestroy() called");
        mFlagNetworkStop = true;
        getApplicationContext().unregisterReceiver(mWifiScanReceiver);
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
                mFlagNetworkStop = false;
                String msg = "Hello! this is android.";
                sendToServer(serverIp, serverPort, msg, false /* polling*/);
                break;

            case ACTION_START_POLLING:
                mFlagNetworkStop = false;
                String payload = getClientPayload(Payload.CLIENT_REQUEST_POLICIES);
                sendToServer(serverIp, serverPort, payload, true /* polling*/);
                break;

            case ACTION_STOP_POLLING:
                mFlagNetworkStop = true;
                break;

            case ACTION_SCAN_WIFI:
                boolean isWifiScanStarted = mWm.startScan();
                activityLog("isWifiScanStarted : " + isWifiScanStarted);
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

    private boolean isValidSignature() {
        boolean ret = false;
        try {
            String servSign = mCurServerReply.getString(Payload.SERVER_SIGN);
            String toBeSigned = mCurServerReply.getString(Payload.TO_BE_SIGNED);
            byte[] signBytes = Base64.decode(servSign, Base64.DEFAULT);
            Signature verifier = Signature.getInstance("SHA256withRSA/PSS",
                    new BouncyCastleProvider());
            verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    32 /*saltLength*/, 1 /*trailer field*/));
            verifier.initVerify(loadCert());
            verifier.update(toBeSigned.getBytes());
            ret = verifier.verify(signBytes);
        } catch (JSONException | NoSuchAlgorithmException | InvalidKeyException |
                SignatureException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        Log.d(LOG_TAG, "isValidSignature() : " + ret);
        return ret;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private String getClientPayload(String cmd) {
        JSONObject payload = new JSONObject();
        try {
            payload.put(Payload.MAGIC, "apm_service");

            JSONObject rsaEnc = new JSONObject();
            rsaEnc.put(Payload.VERSION, "0.1");
            rsaEnc.put(Payload.CMD, cmd);
            rsaEnc.put(Payload.USER_ID, mUserInstanceId);
            payload.put(Payload.RSA_ENC, rsaEncrypt(rsaEnc.toString()));

            payload.put(Payload.SERVER_ALIAS, "UranMdmServer");
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return payload.toString();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
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

    private void sendToServer(String servIp, int servPort, String msg, boolean polling) {
        if (mNetworkThread != null && mNetworkThread.isAlive()) {
            mNetworkThread.interrupt();
        }

        mNetworkThread = new Thread(new Runnable() {
            @Override
            public void run() {
                do {
                    Log.d(LOG_TAG, "Network thread is living! polling: " + polling +
                            ", mFlagNetworkStop: " + mFlagNetworkStop);
                    activityLog("isWifiScanStarted : " + mWm.startScan());

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

                        if (!msg.startsWith("Hello") && isValidSignature() && isValidTimeStamp()
                                && isInPublicArea()) {
                            applyPolicies();
                        }
                        if (polling) {
                            Thread.sleep(2000); // 2 sec.
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
                } while (polling && !mFlagNetworkStop);
            }
        });

        mNetworkThread.start();
    }

    private boolean isValidTimeStamp() {
        boolean ret = false;
        try {
            SimpleDateFormat format = new SimpleDateFormat("yy.MM.dd HH:mm:ss");
            JSONObject toBeSigned = mCurServerReply.getJSONObject(Payload.TO_BE_SIGNED);
            Date timeStamp = format.parse(toBeSigned.getString(Payload.TIME_STAMP));
            Date curTime = new Date();
            ret = (curTime.getTime() - timeStamp.getTime()) < 5000; // 5 sec.
            Log.d(LOG_TAG, "curTime : " + curTime.getTime() + ", timeStamp: " + timeStamp.getTime());
        } catch (ParseException | JSONException e) {
            e.printStackTrace();
        }
        Log.d(LOG_TAG, "isValidTimeStamp() : " + ret);
        return ret;
    }

    private void applyPolicies() {
        try {
            // get policy content
            JSONObject toBeSigned = mCurServerReply.getJSONObject(Payload.TO_BE_SIGNED);
            JSONObject policies = toBeSigned.getJSONObject(Payload.SERVER_REPLY_POLICIES);
            boolean isCameraAllowed = policies.getBoolean(Payload.POLICY_ALLOW_CAMERA);
            Log.d(LOG_TAG, "applyPolicies(), isCameraAllowed : " + isCameraAllowed);

            mDpm.setCameraDisabled(mComponentName, !isCameraAllowed);
            activityLog("Allow camera : " + isCameraAllowed);

        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private boolean isInPublicArea() {
        boolean result = isPublicWiFiScanned() || isPublicBluetoothScanned()
                || isPublicIndoorLocalized();
        Log.d(LOG_TAG, "isInPublicArea(), result : " + result);
        activityLog("isInPublicArea(), result : " + result);

        // NOTE. If the device is out of public area, mdm policy should be released
        if (!result) {
            mDpm.setCameraDisabled(mComponentName, false); // release disable camera policy
        }

        return result;
    }

    private boolean isPublicWiFiScanned() {
        // TODO
        boolean result = false;
        for(ScanResult ap : mLastWiFiScanResult) {
            if (ap.SSID.equals(TEST_PUBLIC_WIFI)) {
                result = true;
                break;
            }
        }
        Log.d(LOG_TAG, "isPublicWiFiScanned(), result : " + result);
        activityLog("isPublicWiFiScanned(), result : " + result);
        return result;
    }

    private boolean isPublicBluetoothScanned() {
        // TODO
        boolean result = false;
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
