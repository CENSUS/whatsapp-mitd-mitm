Java.perform(function() {
    var RESUMPTION_MASTER_SECRET_EVENT = "X.31u";
    var WATLS_TRUST_MANAGER = "X.1Sh";
    var WATLS_STATE = "X.328";

    var _String = Java.use("java.lang.String");
    var HashMap = Java.use("java.util.HashMap");
    var MapEntry = Java.use("java.util.Map$Entry");
    var ReflectArray = Java.use("java.lang.reflect.Array");
    var Integer = Java.use("java.lang.Integer");
    var Exception = Java.use("java.lang.Exception");
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var AllowAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");

    var Log = Java.use("android.util.Log");
    var Base64 = Java.use("android.util.Base64");

    var ResumptionMasterSecretEvent = Java.use(RESUMPTION_MASTER_SECRET_EVENT);
    var WatlsTrustManager = Java.use(WATLS_TRUST_MANAGER);
    var WatlsState = Java.use(WATLS_STATE);


    function hexdump(bytearray) {
        var length = ReflectArray.getLength(bytearray);
        var s = "";
        for(var i = 0; i < length; i++)
        {
            var c = ReflectArray.getByte(bytearray, i);
            if(i != 0 && i % 32 == 0)
                s += "\n";
            s += Integer.toHexString(c & 0x000000ff) + " ";
        }
        return s;
    }


    ////////// CERTIFICATE CHAIN AND HOSTNAME VERIFICATION //////////

    WatlsTrustManager.checkServerTrusted.implementation = function(certs, auth_type) {
        console.log("Verifying certificate chain :-( this shouldn't have happened!");
        // console.log(Log.getStackTraceString(Exception.$new()));
        this.checkServerTrusted(certs, auth_type);
    }

    HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());


    ////////// WATLS EVENT HANDLING //////////

    ResumptionMasterSecretEvent.A00.implementation = function(_1, _2, _3, _4) {
        var ret = this.A00(_1, _2, _3, _4);

        var state = Java.cast(_2, WatlsState);

        var hash_map = Java.cast(state.A0U.value, HashMap);
        var entry_set = hash_map.entrySet();
        var array = entry_set.toArray();

        array.forEach(function(entry) {
            entry = Java.cast(entry, MapEntry);
            console.log(entry.getKey() + " : " + hexdump(entry.getValue()));
        });

        console.log("Chosen PSK is " + hexdump(state.A0I.value.A03.value.pskVal.value));

        return ret;
    }
});


function connect(hostname) {
    Java.perform(function() {
        var MEDIA_DOWNLOAD_CONNECTION = "X.1PF";
        var MEDIA_DOWNLOAD_RESPONSE = "X.24m";

        var MediaDownloadConnection = Java.use(MEDIA_DOWNLOAD_CONNECTION);
        var MediaDownloadResponse = Java.use(MEDIA_DOWNLOAD_RESPONSE);
        var mediaDownloadConnection = MediaDownloadConnection.A00();
        console.log(mediaDownloadConnection);

        var URL = Java.use("java.net.URL");
        var url = URL.$new("https://" + hostname);

        var mediaDownloadResponse = mediaDownloadConnection.A03(url, hostname, "GET");
        mediaDownloadResponse = Java.cast(mediaDownloadResponse, MediaDownloadResponse);

        // console.log(mediaDownloadResponse);
        console.log("Response code : " + mediaDownloadResponse.A2i()); // getResponseCode()
        // console.log(mediaDownloadResponse.getContentLength());
        mediaDownloadResponse.close();
    });
}


function connect_lan() {
    connect("192.168.1.100");
}

function connect_fath() {
    connect("media.fath6-1.fna.whatsapp.net");
}

