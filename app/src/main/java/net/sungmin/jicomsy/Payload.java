package net.sungmin.jicomsy;

public class Payload {

    // json keys: camel case
    static final String MAGIC = "Magic";
    static final String VERSION = "Version";
    static final String RSA_ENC = "RsaEnc";
    static final String CMD = "Cmd";
    static final String USER_ID = "UserId";
    static final String SERVER_ALIAS = "ServAlias";
    static final String TO_BE_SIGNED = "ToBeSigned";
    static final String TIME_STAMP = "TimeStamp";
    static final String SERVER_SIGN = "ServSign";

    // Commands to communicate with MDM server
    static final String CLIENT_REQUEST_POLICIES = "client_request_policies";
    static final String SERVER_REPLY_POLICIES = "server_reply_policies";

    // Policies
    static final String POLICY_ALLOW_CAMERA = "policy_allow_camera";

    // TODO error
}

