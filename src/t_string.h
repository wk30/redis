#ifndef __T_STRING_H
#define __T_STRING_H

#include "redis.h"

void genericSet(redisDb *db, robj *key, robj *val);
void genericSetnx(redisDb *db, robj *key, robj *val);
robj *genericGet(redisDb *db, robj *key);

#endif
