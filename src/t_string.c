#include "t_string.h"
#include "object.h"

void genericSet(redisDb *db, robj *key, robj *val) {
    if (lookupKeyWrite(db, key) == NULL) {
        dbAdd(db,key,val);
    } else {
        dbOverwrite(db,key,val);
    }
    incrRefCount(val);
}

void genericSetnx(redisDb *db, robj *key, robj *val) {
    if (lookupKeyWrite(db,key) != NULL) {
        return;
    }
    genericSet(db,key,val);
}

robj *genericGet(redisDb *db, robj *key) {
    robj *o = lookupKeyRead(db, key);
    if (!o) return NULL;
    return o;
}
