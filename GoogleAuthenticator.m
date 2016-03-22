//
//  GoogleAuthenticator.m
//  ElasticUI
//
//  Created by 谭伟 on 15/9/16.
//  Copyright (c) 2015年 Daniel Tavares. All rights reserved.
//

#import "GoogleAuthenticator.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import "MF_Base32Additions.h"

@implementation GoogleAuthenticator

+(NSString*)hotpWithKey:(NSString*)key time:(NSInteger)time
{
    NSData *HS = [GoogleAuthenticator hmacSha1:key time:(int32_t)time];
    int32_t Snum = [GoogleAuthenticator Dt:HS];
    int32_t D = Snum % (uint32_t)pow(10, 6);
    return [NSString stringWithFormat:@"%06d", D];
}

+(NSString*)hotpWithKey:(NSString*)key
{
    return [GoogleAuthenticator hotpWithKey:key time:[NSDate date].timeIntervalSince1970/30];
}

+(int32_t)Dt:(NSData*)hmac
{
    uint8_t *hs = (uint8_t*)hmac.bytes;
    int32_t offsetBits = hs[19] & 0x0f;
    int32_t p = hs[offsetBits]<<24 | hs[offsetBits+1]<<16 | hs[offsetBits+2]<<8 | hs[offsetBits+3];
    return p & 0x7fffffff;
}

+ (NSData *) hmacSha1:(NSString*)key time:(int32_t)time
{
    NSData *decodeKey = [NSData dataWithBase32String:key];
    
    char cData[8];
    memset(cData, 0, sizeof(cData));
    cData[4] = time >> 24 & 0xff;
    cData[5] = time >> 16 & 0xff;
    cData[6] = time >> 8  & 0xff;
    cData[7] = time >> 0  & 0xff;
    
    uint8_t cHMAC[CC_SHA1_DIGEST_LENGTH];
    memset(cHMAC, 0, sizeof(cHMAC));
    
    CCHmac(kCCHmacAlgSHA1, decodeKey.bytes, strlen(decodeKey.bytes), cData, 8, cHMAC);
    
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:CC_SHA1_DIGEST_LENGTH];
    
    return HMAC;
}
@end
