//
// Created by Nicolas Tichy on 2/17/14.
// Copyright (c) 2014 Cassida Custom Solutions. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import "SecurityTools.h"

static const UInt8 publicKeyIdentifier[] = "de.cameonet.app.publickey\0";
static const UInt8 privateKeyIdentifier[] = "de.cameonet.app.privatekey\0";

@implementation SecurityTools
{
}

+(SecurityTools *)sharedInstance
{
    //  Recommended way according to Apple
    static SecurityTools *sharedInstance = nil;
    static dispatch_once_t onceToken = 0;
    dispatch_once(&onceToken, ^
                  {
                      sharedInstance = [[SecurityTools alloc] init];
                      
                      [sharedInstance getPublicKeyRef];
                      [sharedInstance getPrivateKeyRef];
                  });
    
    return sharedInstance;
}

size_t encodeLength(unsigned char * buf, size_t length)
{
    // encode length in ASN.1 DER format
    if (length < 128)
    {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j)
    {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}

- (void)generateKeyPairPlease
{
    OSStatus status = noErr;
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                        length:strlen((const char *)publicKeyIdentifier)];
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                         length:strlen((const char *)privateKeyIdentifier)];
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                    forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:2048]
                    forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag
                       forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag
                      forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr
                    forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr
                    forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                                &publicKey, &privateKey);
    
    [self addPublicKeyToKeyChain:publicKey];
    [self addPrivateKeyToKeyChain:privateKey];
    
    //    OSStatus sanityCheck = noErr;
    
    //sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
}

- (BOOL)addPublicKeyToKeyChain:(SecKeyRef)givenKey
{
    NSData *publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Temporarily add key to the Keychain, return as data:
    NSMutableDictionary * attributes = [queryPublicKey mutableCopy];
    [attributes setObject:(__bridge id)givenKey forKey:(__bridge id)kSecValueRef];
    
    // Remove from Keychain in case it is there
    (void)SecItemDelete((__bridge CFDictionaryRef) queryPublicKey);
    
    CFTypeRef result = nil;
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
    
    if (sanityCheck == errSecSuccess) // sanityCheck == errSecDuplicateItem
    {
        CFBridgingRelease(result);
    }
    
    return YES;
}

- (BOOL)addPrivateKeyToKeyChain:(SecKeyRef)givenKey
{
    NSData *privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id) kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Temporarily add key to the Keychain, return as data:
    NSMutableDictionary * attributes = [queryPrivateKey mutableCopy];
    [attributes setObject:(__bridge id)givenKey forKey:(__bridge id)kSecValueRef];
    
    // Remove from Keychain in case it is there
    (void)SecItemDelete((__bridge CFDictionaryRef) queryPrivateKey);
    
    CFTypeRef result = nil;
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
    
    if (sanityCheck == errSecSuccess) // sanityCheck == errSecDuplicateItem
    {
        CFBridgingRelease(result);
    }
    
    return YES;
}

- (NSData *)getPublicKeyBitsFromKey:(SecKeyRef)givenKey
{
    [self getPublicKeyRef];
    
    NSData *publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    
    CFDataRef publicKeyBitsRef = nil;
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Temporarily add key to the Keychain, return as data:
    NSMutableDictionary * attributes = [queryPublicKey mutableCopy];
    [attributes setObject:(__bridge id)givenKey forKey:(__bridge id)kSecValueRef];
    [attributes setObject:@YES forKey:(__bridge id)kSecReturnData];
    CFTypeRef result = nil;
    
    (void)SecItemDelete((__bridge CFDictionaryRef) queryPublicKey);
    
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
    if (sanityCheck == errSecSuccess) // sanityCheck == errSecDuplicateItem
    {
        publicKeyBits = CFBridgingRelease(result);
        
        // Remove from Keychain again
        (void)SecItemDelete((__bridge CFDictionaryRef) queryPublicKey);
    }
    else if (sanityCheck == errSecDuplicateItem)
    {
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyBitsRef);
        if (sanityCheck == errSecSuccess)
        {
            publicKeyBits = (__bridge NSData *)publicKeyBitsRef;
        }
        
        // Remove from Keychain again
        (void)SecItemDelete((__bridge CFDictionaryRef) queryPublicKey);
    }
    
    return publicKeyBits;
}

- (NSData *)getPrivateKeyBitsFromKey:(SecKeyRef)givenKey
{
    [self getPrivateKeyRef];
    
    NSData *privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    
    OSStatus sanityCheck = noErr;
    NSData * privateKeyBits = nil;
    
    CFDataRef privateKeyBitsRef = nil;
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Temporarily add key to the Keychain, return as data:
    NSMutableDictionary * attributes = [queryPrivateKey mutableCopy];
    [attributes setObject:(__bridge id)givenKey forKey:(__bridge id)kSecValueRef];
    [attributes setObject:@YES forKey:(__bridge id)kSecReturnData];
    CFTypeRef result = nil;
    
    (void)SecItemDelete((__bridge CFDictionaryRef) queryPrivateKey);
    
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) attributes, &result);
    if (sanityCheck == errSecSuccess) // sanityCheck == errSecDuplicateItem
    {
        privateKeyBits = CFBridgingRelease(result);
        
        // Remove from Keychain again
        (void)SecItemDelete((__bridge CFDictionaryRef) queryPrivateKey);
    }
    else if (sanityCheck == errSecDuplicateItem)
    {
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyBitsRef);
        if (sanityCheck == errSecSuccess)
        {
            privateKeyBits = (__bridge NSData *)privateKeyBitsRef;
        }
        
        // Remove from Keychain again
        (void)SecItemDelete((__bridge CFDictionaryRef) queryPrivateKey);
    }
    
    return privateKeyBits;
}

- (NSData *)getPublicKeyBits
{
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;
    CFDataRef publicKeyBitsRef = nil;
    
    NSData *publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyBitsRef);
    
    if (sanityCheck == errSecSuccess)
    {
        publicKeyBits = (__bridge NSData *)publicKeyBitsRef;
    }
    
    return publicKeyBits;
}

- (NSData *)getPrivateKeyBits
{
    OSStatus sanityCheck = noErr;
    NSData * privateKeyBits = nil;
    CFDataRef privateKeyBitsRef = nil;
    
    NSData *privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyBitsRef);
    
    if (sanityCheck == errSecSuccess)
    {
        privateKeyBits = (__bridge NSData *)privateKeyBitsRef;
    }
    
    return privateKeyBits;
}

- (SecKeyRef)getPublicKeyRef
{
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKey == nil)
    {
        NSData *publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                           length:strlen((const char *)publicKeyIdentifier)];
        
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        if (sanityCheck != noErr)
        {
            [self generateKeyPairPlease];
            publicKeyReference = publicKey;
        }
        else
        {
            publicKey = publicKeyReference;
        }
    }
    else
    {
        publicKeyReference = publicKey;
    }
    
    return publicKeyReference;
}

- (SecKeyRef)getPrivateKeyRef
{
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (privateKey == nil)
    {
        NSData *publicTag = [NSData dataWithBytes:privateKeyIdentifier
                                           length:strlen((const char *)privateKeyIdentifier)];
        
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        
        if (sanityCheck != noErr)
        {
            [self generateKeyPairPlease];
            privateKeyReference = privateKey;
        }
        else
        {
            privateKey = privateKeyReference;
        }
    }
    else
    {
        privateKeyReference = privateKey;
    }
    
    return privateKeyReference;
}

- (NSString *)getRSAPublicKeyAsBase64
{
    static const unsigned char _encodedRSAEncryptionOID[15] =
    {
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    
    NSData * publicKeyBits = [self getPublicKeyBitsFromKey:publicKey];
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([publicKeyBits length ] + 1  < 128 )
    {
        bitstringEncLength = 1 ;
    }
    else
    {
        bitstringEncLength = (int)(([publicKeyBits length ] +1 ) / 256 ) + 2 ;
    }
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength + [publicKeyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [publicKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:publicKeyBits];
    
    NSString* b64key = [encKey base64EncodedStringWithOptions: NSDataBase64Encoding76CharacterLineLength];
    NSString* key = [NSString stringWithFormat:@"-----BEGIN PUBLIC KEY-----\n%@\n-----END PUBLIC KEY-----\n", b64key];
    
    return key;
}

- (NSString *)getRSAPrivateKeyAsBase64
{
    static const unsigned char _encodedRSAEncryptionOID[15] =
    {
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    
    NSData * privateKeyBits = [self getPrivateKeyBitsFromKey:privateKey];
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    // When we get to the bitstring - how will we encode it?
    if  ([privateKeyBits length ] + 1  < 128 )
    {
        bitstringEncLength = 1 ;
    }
    else
    {
        bitstringEncLength = (int)(([privateKeyBits length ] +1 ) / 256 ) + 2 ;
    }
    
    // Overall we have a sequence of a certain length
    builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
    // Build up overall size made up of -
    // size of OID + size of bitstring encoding + size of actual key
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength + [privateKeyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    // First part of the sequence is the OID
    [encKey appendBytes:_encodedRSAEncryptionOID length:sizeof(_encodedRSAEncryptionOID)];
    
    // Now add the bitstring
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [privateKeyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    // Now the actual key
    [encKey appendData:privateKeyBits];
    
    NSString* b64key = [encKey base64EncodedStringWithOptions: NSDataBase64Encoding76CharacterLineLength];
    NSString* key = [NSString stringWithFormat:@"-----BEGIN PRIVATE KEY-----\n%@\n-----END PRIVATE KEY-----\n", b64key];
    
    return key;
}


+ (NSData *)sha256:(NSData *)data
{
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    if ( CC_SHA256([data bytes], (CC_LONG)[data length], hash) )
    {
        NSData *sha1 = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        return sha1;
    }
    return nil;
}

-(NSString *)signWithPrivateKey:(NSString* )string
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize;
    uint8_t *cipherBuffer;
    
    NSData *someData = [SecurityTools sha256:[string dataUsingEncoding:NSUTF8StringEncoding]];
    const void *bytes = [someData bytes];
    
    const uint8_t *dataToEncrypt = bytes;
    
    cipherBufferSize = SecKeyGetBlockSize(privateKey);
    cipherBuffer = malloc(cipherBufferSize);
    
    memset(cipherBuffer, 0, cipherBufferSize);
    
    if (cipherBufferSize < sizeof(dataToEncrypt))
    {
        // Ordinarily, you would split the data up into blocks
        // equal to cipherBufferSize, with the last block being
        // shorter. For simplicity, this example assumes that
        // the data is short enough to fit.
        printf("Could not decrypt.  Packet too large.\n");
        return NULL;
    }
    
    status = SecKeyRawSign(privateKey, kSecPaddingPKCS1SHA256, dataToEncrypt,  CC_SHA256_DIGEST_LENGTH, cipherBuffer,
                           &cipherBufferSize);
    
    free(cipherBuffer);
    
    NSString *str = [[NSString alloc] initWithData:[[SecurityTools getSignatureBytes:[string dataUsingEncoding:NSUTF8StringEncoding] withPrivateKey:privateKey] base64EncodedDataWithOptions:0]
                                          encoding:NSUTF8StringEncoding];
    
    NSString *ret = [NSString stringWithFormat:@"RSA-SHA256 %@", str];
    
    return ret;
}

+ (NSData *)getSignatureBytes:(NSData *)plainText withPrivateKey:(SecKeyRef)privateKey
{
    OSStatus status = noErr;
    NSData * signedHash = nil;
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    void *signedHashBytes = malloc( signedHashBytesSize );
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    status = SecKeyRawSign(privateKey,
                           kSecPaddingPKCS1SHA256,
                           (const uint8_t *)[[SecurityTools sha256:plainText] bytes],
                           CC_SHA256_DIGEST_LENGTH,
                           (uint8_t *)signedHashBytes,
                           &signedHashBytesSize);
    
    signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
    
    if (signedHashBytes) free(signedHashBytes);
    
    return signedHash;
}

@end