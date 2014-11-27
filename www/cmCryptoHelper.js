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

    this.encrypt = function(win, fail, publicKey, plainText) {
        exec(win, fail, "cmCryptoHelper", "encrypt", [publicKey, plainText]);
    }

    this.decrypt = function(win, fail, privateKey, encryptedText) {
        exec(win, fail, "cmCryptoHelper", "decrypt", [privateKey, encryptedText]);
    }

    this.sign = function(win, fail, publicKey, text) {
        exec(win, fail, "cmCryptoHelper", "sign", [publicKey, text]);
    }

    this.verify = function(win, fail, publicKey, text, signature) {
        exec(win, fail, "cmCryptoHelper", "verify", [privateKey, text, signature]);
    }

}

module.exports = new cmCryptoHelper();
