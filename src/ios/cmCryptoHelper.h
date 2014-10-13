#import <Cordova/CDVPlugin.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface cmCryptoHelper : CDVPlugin

- (void) getPublicKey:(CDVInvokedUrlCommand*) command;
- (void) getPrivateKey:(CDVInvokedUrlCommand*) command;

@end