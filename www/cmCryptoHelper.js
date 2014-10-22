var argscheck = require('cordova/argscheck'),
    channel = require('cordova/channel'),
    exec = require('cordova/exec'),
    cordova = require('cordova');

// channel.createSticky('onCordovaInfoReady');
// Tell cordova channel to wait on the CordovaInfoReady event
// channel.waitForInitialization('onCordovaInfoReady');

function cmCryptoHelper() {
	
	this.getPrivateKey = function(win, fail, keySize) {
		exec(win, fail, "cmCryptoHelper", "getPrivateKey", [keySize]);
	}
}

module.exports = new cmCryptoHelper();
