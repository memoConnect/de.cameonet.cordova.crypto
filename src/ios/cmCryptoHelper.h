#import <Cordova/CDVPlugin.h>

@interface cmCryptoHelper : CDVPlugin

- (void) getPrivateKey:(CDVInvokedUrlCommand*) command;

- (void) encrypt:(CDVInvokedUrlCommand*) command;


@end