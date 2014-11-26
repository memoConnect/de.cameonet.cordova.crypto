#import "cmCryptoHelper.h"

#import "openssl/rsa.h"
#import "openssl/pem.h"

@implementation cmCryptoHelper


- (void)getPrivateKey:(CDVInvokedUrlCommand*)command
{
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
    NSString* callbackId = [command callbackId];

    NSString* publicKey = [command.arguments objectAtIndex:0];
    NSString* plainText = [command.arguments objectAtIndex:1];

    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{

        NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];

        const unsigned char * key = (const unsigned char *) [publicKey UTF8String];

        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, 0, NULL);

        int maxSize = RSA_size(rsa);
        unsigned char *encrypted = (unsigned char *) malloc(maxSize * sizeof(char));

        int bytes = RSA_public_encrypt((int)[data length], [data bytes], encrypted, rsa, RSA_PKCS1_PADDING);

        NSData *encryptedData = [NSData dataWithBytes:encrypted length:bytes];

        NSString * encryptedBase64 = [encryptedData base64Encoding];

        CDVPluginResult* result = [CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_OK
                                   messageAsString: encryptedBase64];

        BIO_free(bio);

        [self success:result callbackId:callbackId];
    });
}


- (void)decrypt:(CDVInvokedUrlCommand*)command
{
    NSString* callbackId = [command callbackId];

    NSString* privateKey = [command.arguments objectAtIndex:0];
    NSString* encryptedBase64 = [command.arguments objectAtIndex:1];

    // start queue for key generation
    dispatch_queue_t myQueue = dispatch_queue_create("OpenSSL",NULL);
    dispatch_async(myQueue, ^{

        NSData * encryptedData = [[NSData alloc] initWithBase64EncodedString:encryptedBase64 options:0];

        const unsigned char * key = (const unsigned char *) [privateKey UTF8String];

        BIO *bio = BIO_new_mem_buf((void*)key, (int)strlen(key));
        RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, NULL);

        int maxSize = encryptedBase64.length;
        unsigned char *decrypted = (unsigned char *) malloc(maxSize * sizeof(char));

        int bytes = RSA_private_decrypt((int)[encryptedData length], [encryptedData bytes], decrypted, rsa, RSA_PKCS1_PADDING);

        NSData *decryptedData = [NSData dataWithBytes:decrypted length:bytes];

        NSString * decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];

        CDVPluginResult* result = [CDVPluginResult
                                   resultWithStatus:CDVCommandStatus_OK
                                   messageAsString: decryptedString];

        BIO_free(bio);
        RSA_free(rsa);

        [self success:result callbackId:callbackId];
    });
}






@end