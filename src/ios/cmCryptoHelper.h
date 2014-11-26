#import <Cordova/CDVPlugin.h>

@interface cmCryptoHelper : CDVPlugin

- (void) getPrivateKey:(CDVInvokedUrlCommand*) command;

- (void) encrypt:(CDVInvokedUrlCommand*) command;

- (void) decrypt:(CDVInvokedUrlCommand*) command;

- (void) sign:(CDVInvokedUrlCommand*) command;

- (void) verify:(CDVInvokedUrlCommand*) command;

@end