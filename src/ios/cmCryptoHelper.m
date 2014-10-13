#import "cmCryptoHelper.h"
#import "SecurityTools.h"

@implementation cmCryptoHelper

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;

- (void)getPublicKey:(CDVInvokedUrlCommand*)command
{
    NSString* callbackId = [command callbackId];
    //NSUInteger* keySizeParam = [[command arguments] objectAtIndex:0];

    NSString *publicKey = [[SecurityTools sharedInstance] getRSAPublicKeyAsBase64];

    CDVPluginResult* result = [CDVPluginResult
                               resultWithStatus:CDVCommandStatus_OK
                               messageAsString: publicKey];

    [self success:result callbackId:callbackId];
}

- (void)getPrivateKey:(CDVInvokedUrlCommand*)command
{
    NSString* callbackId = [command callbackId];
    //NSUInteger* keySizeParam = [[command arguments] objectAtIndex:0];

    NSString *privateKey = [[SecurityTools sharedInstance] getRSAPrivateKeyAsBase64];
    
    CDVPluginResult* result = [CDVPluginResult
                               resultWithStatus:CDVCommandStatus_OK
                               messageAsString: privateKey];

    [self success:result callbackId:callbackId];
}
@end