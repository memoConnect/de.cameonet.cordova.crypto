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
@end