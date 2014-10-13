//
// Created by Nicolas Tichy on 2/17/14.
// Copyright (c) 2014 Cassida Custom Solutions. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface SecurityTools : NSObject
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;

}

+(SecurityTools *)sharedInstance;
-(NSString *)getRSAPublicKeyAsBase64;
-(NSString *)getRSAPrivateKeyAsBase64;
-(NSString *)signWithPrivateKey:(NSString* )string;


@end