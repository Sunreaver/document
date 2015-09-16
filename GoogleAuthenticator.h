//
//  GoogleAuthenticator.h
//  ElasticUI
//
//  Created by 谭伟 on 15/9/16.
//  Copyright (c) 2015年 Daniel Tavares. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface GoogleAuthenticator : NSObject

+(NSString*)hotpWithKey:(NSString*)key time:(NSInteger)time;
+(NSString*)hotpWithKey:(NSString*)key;

@end
