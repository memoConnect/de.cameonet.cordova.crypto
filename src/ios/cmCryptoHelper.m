#import "cmCryptoHelper.h"

#import "openssl/rsa.h"
#import "openssl/pem.h"

@implementation cmCryptoHelper


- (void)getPrivateKey:(CDVInvokedUrlCommand*)command
{
    NSLog(@"cmCryptoHelper Plugin: generate key");
    
    
    NSString* callbackId = [command callbackId];
    
    NSString* sBits = [command.arguments objectAtIndex:0];
    
    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{
        
        int kBits = [sBits intValue];
        
        //NSLog(@"BITS: %i", kBits);
        
        RSA *rsa = NULL;
        BIGNUM *bne = NULL;
        
        unsigned long   e = RSA_F4;
        
        // generate rsa key
        bne = BN_new();
        BN_set_word(bne,e);
        rsa = RSA_new();
        RSA_generate_key_ex(rsa, kBits, bne, NULL);
        
        /* To get the C-string PEM form: */
        int keylen;
        char *pem_key;
        
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
        
        keylen = BIO_pending(bio);
        pem_key = calloc(keylen+1, 1); /* Null-terminate */
        BIO_read(bio, pem_key, keylen);
        
        NSString *privateKey =[NSString stringWithFormat:@"%s", pem_key];
        
        BIO_free_all(bio);
        RSA_free(rsa);
        BN_free(bne);
        free(pem_key);
        
        CDVPluginResult* result = [CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_OK
                                   messageAsString: privateKey];
        
        [self success:result callbackId:callbackId];
        
    });
}


- (void)encrypt:(CDVInvokedUrlCommand*)command
{
    NSLog(@"cmCryptoHelper Plugin: encrypt");
    
    NSString* callbackId = [command callbackId];
    
    NSString* publicKey = [command.arguments objectAtIndex:0];
    NSString* plainText = [command.arguments objectAtIndex:1];
    
    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{
        
        NSData * data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
        
        char * key = (char *) [publicKey UTF8String];
        
        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, 0, NULL);
        
        int size = RSA_size(rsa);
        unsigned char * encrypted = (unsigned char *) malloc(size);
        
        int bytes = RSA_public_encrypt((int)[data length], [data bytes], encrypted, rsa, RSA_PKCS1_PADDING);
        
        if(bytes < 0) {
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_ERROR
                                       messageAsString: @"openssl error"];
            
            [self error: result callbackId:callbackId];
            
        } else {
            
            NSData *encryptedData = [NSData dataWithBytes:encrypted length:bytes];
            
            NSString * encryptedBase64 = [encryptedData base64Encoding];
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_OK
                                       messageAsString: encryptedBase64];
            
            [self success:result callbackId:callbackId];
        }
        
        free(encrypted);
        BIO_free_all(bio);
        RSA_free(rsa);
        
    });
}

- (void)decrypt:(CDVInvokedUrlCommand*)command
{
    NSLog(@"cmCryptoHelper Plugin: decrypt");
    
    NSString* callbackId = [command callbackId];
    
    NSString* privateKey = [command.arguments objectAtIndex:0];
    NSString* encryptedBase64 = [command.arguments objectAtIndex:1];
    
    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{
        
        NSData * encryptedData = [[NSData alloc] initWithBase64EncodedString:encryptedBase64 options:0];
        
        char * key = (char *) [privateKey UTF8String];
        
        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, NULL);
        
        int maxSize = RSA_size(rsa);
        unsigned char *decrypted = (unsigned char *) malloc(maxSize);
        
        int bytes = RSA_private_decrypt((int)[encryptedData length], [encryptedData bytes], decrypted, rsa, RSA_PKCS1_PADDING);
        
        if(bytes < 0) {
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_ERROR
                                       messageAsString: @"openssl error"];
            
            [self error: result callbackId:callbackId];
            
        } else {
            
            NSData *decryptedData = [NSData dataWithBytes:decrypted length:bytes];
            
            NSString * decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_OK
                                       messageAsString: decryptedString];
            
            [self success:result callbackId:callbackId];
        }
        
        free(decrypted);
        BIO_free(bio);
        RSA_free(rsa);
        
    });
}


-(NSString*) NSDataToHex:(NSData*)data
{
    const unsigned char *dbytes = [data bytes];
    NSMutableString *hexStr =
    [NSMutableString stringWithCapacity:[data length]*2];
    int i;
    for (i = 0; i < [data length]; i++) {
        [hexStr appendFormat:@"%02x", dbytes[i]];
    }
    return [NSString stringWithString: hexStr];
}

- (void)sign:(CDVInvokedUrlCommand*)command
{
    NSLog(@"cmCryptoHelper Plugin: sign");
    
    
    
    NSString* callbackId = [command callbackId];
    
    NSString* privateKey = [command.arguments objectAtIndex:0];
    NSString* text = [command.arguments objectAtIndex:1];
    
    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{
        
        char * key = (char *) [privateKey UTF8String];
        
        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, NULL);
        
        NSData * data = [text dataUsingEncoding:NSUTF8StringEncoding];
        
        // add padding
        int maxSize = RSA_size(rsa);
        unsigned char * paddedData = (unsigned char *) malloc(maxSize);
        RSA_padding_add_PKCS1_type_2(paddedData, maxSize, [data bytes], (int)[data length]);
        
        // create signature
        unsigned char *signature = (unsigned char *) malloc(maxSize);
        int bytes = RSA_private_encrypt(maxSize, paddedData,signature, rsa, RSA_NO_PADDING);
        
        if(bytes < 0) {
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_ERROR
                                       messageAsString: @"openssl error"];
            
            [self error: result callbackId:callbackId];
            
        } else {
            NSData * signatureData = [NSData dataWithBytes:signature length:bytes];
            NSString * signatureHex = [self NSDataToHex:signatureData];
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_OK
                                       messageAsString: signatureHex];
            
            [self success:result callbackId:callbackId];
        }
        
        free(paddedData);
        free(signature);
        BIO_free(bio);
        RSA_free(rsa);
    });
}

- (NSData *)hexToNSData:(NSString *) string {
    const char *chars = [string UTF8String];
    int i = 0, len = string.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    
    return data;
}



- (void)verify:(CDVInvokedUrlCommand*)command
{
    NSLog(@"cmCryptoHelper Plugin: verify");
    
    NSString* callbackId = [command callbackId];
    
    NSString* publicKey = [command.arguments objectAtIndex:0];
    NSString* text = [command.arguments objectAtIndex:1];
    NSString* signature = [command.arguments objectAtIndex:2];
    
    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{
        
        char * key = (char *) [publicKey UTF8String];
        
        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, 0, NULL);
        
        NSData * singatureData = [self hexToNSData:signature];
        
        // get signed text
        int maxSize = RSA_size(rsa) * sizeof(char) * 2;
        unsigned char * signedText = (unsigned char *) malloc(maxSize);
        int decryptBytes = RSA_public_decrypt((int)[singatureData length], [singatureData bytes], signedText, rsa, RSA_NO_PADDING);
        
        if(decryptBytes < 0) {
            
            CDVPluginResult* result = [CDVPluginResult
                                       resultWithStatus:CDVCommandStatus_ERROR
                                       messageAsString: @"openssl error"];
            
            [self error: result callbackId:callbackId];
            
        } else {
            
            // remove padding
            signedText ++;
            unsigned char * removedPadding = (unsigned char *) malloc(maxSize);
            int bytes = RSA_padding_check_PKCS1_type_2(removedPadding, maxSize, signedText, decryptBytes -1, RSA_size(rsa));
            
            if(bytes < 0) {
                
                CDVPluginResult* result = [CDVPluginResult
                                           resultWithStatus:CDVCommandStatus_ERROR
                                           messageAsString: @"openssl error"];
                
                [self error: result callbackId:callbackId];
                
            } else {
                
                // check if both texts match
                NSData * signedData = [NSData dataWithBytes:removedPadding length:bytes];
                NSData * originalData = [text dataUsingEncoding:NSUTF8StringEncoding];
                
                NSString * res = [signedData isEqualToData:originalData] ? @"true" : @"false";
                
                CDVPluginResult* result = [CDVPluginResult
                                           resultWithStatus:CDVCommandStatus_OK
                                           messageAsString: res];
                
                
                [self success:result callbackId:callbackId];
            }
            free(removedPadding);

        }
        
        BIO_free(bio);
        RSA_free(rsa);
    });
}


@end