Java.perform(function() {

    var NOISE_HANDSHAKE = "X.2vT";
    var EXPIRATION_CHECKER = "X.0wJ";
    var MESSAGE_HANDLER = "X.1Pz";

    var _Date = Java.use("java.util.Date");
    var ActivityThread = Java.use("android.app.ActivityThread");
    var Intent = Java.use("android.content.Intent");
    var ComponentName = Java.use("android.content.ComponentName");

    var NoiseHandshake = Java.use(NOISE_HANDSHAKE);
    var ExpirationChecker = Java.use(EXPIRATION_CHECKER);
    var MessageHandler = Java.use(MESSAGE_HANDLER);

    //
    // Hook the constructor of the class responsible for carrying out the Noise
    // protocol handshake.
    //
    NoiseHandshake.$init.implementation = function(_1, _2, loginProtobufMessage, _3, _4, _5, _6, _7) {

        // console.log("Modified login protocol buffer");
        send("Modified login protocol buffer");

        //
        // Get software information sub-packet.
        //
        var softwareInformationProtobufMessage = loginProtobufMessage.A0D.value;

        //
        // Get WhatsApp version information sub-packet.
        //
        var whatsappVersionProtobufMessage = softwareInformationProtobufMessage.A03.value;

        //
        // Change WhatsApp version to something newer than 2.19.355 so that we
        // can log-in to the WhatsApp network.
        //
        whatsappVersionProtobufMessage.A01.value = 2;
        whatsappVersionProtobufMessage.A03.value = 20;
        whatsappVersionProtobufMessage.A04.value = 195;

        return this.$init(_1, _2, loginProtobufMessage, _3, _4, _5, _6, _7);
    }

    //
    // Get `ExpirationChecker' singleton instance.
    //
    var expirationChecker = ExpirationChecker.A00();

    //
    // Check if WhatsApp has expired and install hooks only if it has.
    //
    if(expirationChecker.A03() == true || expirationChecker.A04() == true) {

        // console.log("WhatsApp has expired, hooking!");
        send("WhatsApp has expired, hooking!");

        //
        // Hook `computeExpirationDate()' and make it return a date very far in
        // the future.
        //
        ExpirationChecker.A02.implementation = function() {
            return _Date.$new(31337, 1, 1);
        }

        //
        // Set `checkedAndExpiredDate' to null.
        //
        expirationChecker._A00.value = null;

        //
        // Set `hasExpired' to false.
        //
        expirationChecker._A01.value = false;

        //
        // Check if WhatsApp is still expired. It shouldn't be.
        //
        if(expirationChecker.A03() == false && expirationChecker.A04() == false) {

            // console.log("Expiration bypass successful, starting activity!");
            send("Expiration bypass successful, starting activity!");

            //
            // Get current application context.
            //
            var context = ActivityThread.currentApplication();

            //
            // Restart the WhatsApp home activity.
            //
            var component = ComponentName.$new(context, "com.whatsapp.HomeActivity");

            //
            // Build new intent. It's important to set the following two flags, so
            // that the expiration activity is removed from the activity stack.
            //
            var intent = Intent.$new();
            intent.setComponent(component);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK.value |
                Intent.FLAG_ACTIVITY_NEW_TASK.value);

            //
            // Restart the home activity.
            //
            context.startActivity(intent);

            // console.log("Scheduling reconnect");
            send("Scheduling reconnect");

            //
            // Schedule reconnect.
            //
            MessageHandler.A00().A08();
        }
    }
});
