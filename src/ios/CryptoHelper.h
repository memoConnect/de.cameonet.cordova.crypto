#import <Cordova/CDVPlugin.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface CryptoHelper : CDVPlugin

- (void) getPublicKey:(CDVInvokedUrlCommand*) command;
- (void) getPrivateKey:(CDVInvokedUrlCommand*) command;

@end