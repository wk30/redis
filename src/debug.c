/*
 * Copyright (c) 2009-2020, Salvatore Sanfilippo <antirez at gmail dot com>
 * Copyright (c) 2020, Redis Labs, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "redis.h"
#include "sha1.h"   /* SHA1 is used for DEBUG DIGEST */
#include "crc64.h"
#include "bio.h"
#include "object.h"
#include "t_hash.h"
#include "t_list.h"
#include "t_set.h"
#include "t_zset.h"
#include "ziplist.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#ifndef __OpenBSD__
#include <ucontext.h>
#else
typedef ucontext_t sigcontext_t;
#endif
#endif /* HAVE_BACKTRACE */

#ifdef __CYGWIN__
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000
#endif
#endif

/* Globals */
static int bug_report_start = 0; /* True if bug report header was already logged. */
static pthread_mutex_t bug_report_start_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
void bugReportStart(void);
void printCrashReport(void);
void bugReportEnd(int killViaSignal, int sig);
void logStackTrace(void *eip, int uplevel);

/* ================================= Debugging ============================== */

/* Compute the sha1 of string at 's' with 'len' bytes long.
 * The SHA1 is then xored against the string pointed by digest.
 * Since xor is commutative, this operation is used in order to
 * "add" digests relative to unordered elements.
 *
 * So digest(a,b,c,d) will be the same of digest(b,a,c,d) */
void xorDigest(unsigned char *digest, void *ptr, size_t len) {
    SHA1_CTX ctx;
    unsigned char hash[20], *s = ptr;
    int j;

    SHA1Init(&ctx);
    SHA1Update(&ctx,s,len);
    SHA1Final(hash,&ctx);

    for (j = 0; j < 20; j++)
        digest[j] ^= hash[j];
}

void xorStringObjectDigest(unsigned char *digest, robj *o) {
    o = getDecodedObject(o);
    xorDigest(digest,o->ptr,sdslen(o->ptr));
    decrRefCount(o);
}

/* This function instead of just computing the SHA1 and xoring it
 * against digest, also perform the digest of "digest" itself and
 * replace the old value with the new one.
 *
 * So the final digest will be:
 *
 * digest = SHA1(digest xor SHA1(data))
 *
 * This function is used every time we want to preserve the order so
 * that digest(a,b,c,d) will be different than digest(b,c,d,a)
 *
 * Also note that mixdigest("foo") followed by mixdigest("bar")
 * will lead to a different digest compared to "fo", "obar".
 */
void mixDigest(unsigned char *digest, void *ptr, size_t len) {
    SHA1_CTX ctx;
    char *s = ptr;

    xorDigest(digest,s,len);
    SHA1Init(&ctx);
    SHA1Update(&ctx,digest,20);
    SHA1Final(digest,&ctx);
}

void mixStringObjectDigest(unsigned char *digest, robj *o) {
    o = getDecodedObject(o);
    mixDigest(digest,o->ptr,sdslen(o->ptr));
    decrRefCount(o);
}

/* This function computes the digest of a data structure stored in the
 * object 'o'. It is the core of the DEBUG DIGEST command: when taking the
 * digest of a whole dataset, we take the digest of the key and the value
 * pair, and xor all those together.
 *
 * Note that this function does not reset the initial 'digest' passed, it
 * will continue mixing this object digest to anything that was already
 * present. */
void xorObjectDigest(redisDb *db, robj *keyobj, unsigned char *digest, robj *o) {
    uint32_t aux = htonl(o->type);
    mixDigest(digest,&aux,sizeof(aux));
    long long expiretime = getExpire(db,keyobj);
    char buf[128];

    /* Save the key and associated value */
    if (o->type == OBJ_STRING) {
        mixStringObjectDigest(digest,o);
    } else if (o->type == OBJ_LIST) {
        listTypeIterator *li = listTypeInitIterator(o,0,LIST_TAIL);
        listTypeEntry entry;
        while(listTypeNext(li,&entry)) {
            robj *eleobj = listTypeGet(&entry);
            mixStringObjectDigest(digest,eleobj);
            decrRefCount(eleobj);
        }
        listTypeReleaseIterator(li);
    } else if (o->type == OBJ_SET) {
        setTypeIterator *si = setTypeInitIterator(o);
        sds sdsele;
        while((sdsele = setTypeNextObject(si)) != NULL) {
            xorDigest(digest,sdsele,sdslen(sdsele));
            sdsfree(sdsele);
        }
        setTypeReleaseIterator(si);
    } else if (o->type == OBJ_ZSET) {
        unsigned char eledigest[20];

        if (o->encoding == OBJ_ENCODING_ZIPLIST) {
            unsigned char *zl = o->ptr;
            unsigned char *eptr, *sptr;
            unsigned char *vstr;
            unsigned int vlen;
            long long vll;
            double score;

            eptr = ziplistIndex(zl,0);
            serverAssert(eptr != NULL);
            sptr = ziplistNext(zl,eptr);
            serverAssert(sptr != NULL);

            while (eptr != NULL) {
                serverAssert(ziplistGet(eptr,&vstr,&vlen,&vll));
                score = zzlGetScore(sptr);

                memset(eledigest,0,20);
                if (vstr != NULL) {
                    mixDigest(eledigest,vstr,vlen);
                } else {
                    ll2string(buf,sizeof(buf),vll);
                    mixDigest(eledigest,buf,strlen(buf));
                }

                snprintf(buf,sizeof(buf),"%.17g",score);
                mixDigest(eledigest,buf,strlen(buf));
                xorDigest(digest,eledigest,20);
                zzlNext(zl,&eptr,&sptr);
            }
        } else if (o->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = o->ptr;
            dictIterator *di = dictGetIterator(zs->dict);
            dictEntry *de;

            while((de = dictNext(di)) != NULL) {
                sds sdsele = dictGetKey(de);
                double *score = dictGetVal(de);

                snprintf(buf,sizeof(buf),"%.17g",*score);
                memset(eledigest,0,20);
                mixDigest(eledigest,sdsele,sdslen(sdsele));
                mixDigest(eledigest,buf,strlen(buf));
                xorDigest(digest,eledigest,20);
            }
            dictReleaseIterator(di);
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else if (o->type == OBJ_HASH) {
        hashTypeIterator *hi = hashTypeInitIterator(o);
        while (hashTypeNext(hi) != C_ERR) {
            unsigned char eledigest[20];
            sds sdsele;

            memset(eledigest,0,20);
            sdsele = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_KEY);
            mixDigest(eledigest,sdsele,sdslen(sdsele));
            sdsfree(sdsele);
            sdsele = hashTypeCurrentObjectNewSds(hi,OBJ_HASH_VALUE);
            mixDigest(eledigest,sdsele,sdslen(sdsele));
            sdsfree(sdsele);
            xorDigest(digest,eledigest,20);
        }
        hashTypeReleaseIterator(hi);
    } else if (o->type == OBJ_STREAM) {
        streamIterator si;
        streamIteratorStart(&si,o->ptr,NULL,NULL,0);
        streamID id;
        int64_t numfields;

        while(streamIteratorGetID(&si,&id,&numfields)) {
            sds itemid = sdscatfmt(sdsempty(),"%U.%U",id.ms,id.seq);
            mixDigest(digest,itemid,sdslen(itemid));
            sdsfree(itemid);

            while(numfields--) {
                unsigned char *field, *value;
                int64_t field_len, value_len;
                streamIteratorGetField(&si,&field,&value,
                                           &field_len,&value_len);
                mixDigest(digest,field,field_len);
                mixDigest(digest,value,value_len);
            }
        }
        streamIteratorStop(&si);
    } else {
        serverPanic("Unknown object type");
    }
    /* If the key has an expire, add it to the mix */
    if (expiretime != -1) xorDigest(digest,"!!expire!!",10);
}

/* Compute the dataset digest. Since keys, sets elements, hashes elements
 * are not ordered, we use a trick: every aggregate digest is the xor
 * of the digests of their elements. This way the order will not change
 * the result. For list instead we use a feedback entering the output digest
 * as input in order to ensure that a different ordered list will result in
 * a different digest. */
void computeDatasetDigest(unsigned char *final) {
    unsigned char digest[20];
    dictIterator *di = NULL;
    dictEntry *de;
    int j;
    uint32_t aux;

    memset(final,0,20); /* Start with a clean result */

    for (j = 0; j < server.dbnum; j++) {
        redisDb *db = server.db+j;

        if (dictSize(db->dict) == 0) continue;
        di = dictGetSafeIterator(db->dict);

        /* hash the DB id, so the same dataset moved in a different
         * DB will lead to a different digest */
        aux = htonl(j);
        mixDigest(final,&aux,sizeof(aux));

        /* Iterate this DB writing every entry */
        while((de = dictNext(di)) != NULL) {
            sds key;
            robj *keyobj, *o;

            memset(digest,0,20); /* This key-val digest */
            key = dictGetKey(de);
            keyobj = createStringObject(key,sdslen(key));

            mixDigest(digest,key,sdslen(key));

            o = dictGetVal(de);
            xorObjectDigest(db,keyobj,digest,o);

            /* We can finally xor the key-val digest to the final digest */
            xorDigest(final,digest,20);
            decrRefCount(keyobj);
        }
        dictReleaseIterator(di);
    }
}

#ifdef USE_JEMALLOC
void mallctl_int(client *c, robj **argv, int argc) {
    int ret;
    /* start with the biggest size (int64), and if that fails, try smaller sizes (int32, bool) */
    int64_t old = 0, val;
    if (argc > 1) {
        long long ll;
        if (getLongLongFromObjectOrReply(c, argv[1], &ll, NULL) != C_OK)
            return;
        val = ll;
    }
    size_t sz = sizeof(old);
    while (sz > 0) {
        if ((ret=je_mallctl(argv[0]->ptr, &old, &sz, argc > 1? &val: NULL, argc > 1?sz: 0))) {
            if (ret == EPERM && argc > 1) {
                /* if this option is write only, try just writing to it. */
                if (!(ret=je_mallctl(argv[0]->ptr, NULL, 0, &val, sz))) {
                    addReply(c, shared.ok);
                    return;
                }
            }
            if (ret==EINVAL) {
                /* size might be wrong, try a smaller one */
                sz /= 2;
#if BYTE_ORDER == BIG_ENDIAN
                val <<= 8*sz;
#endif
                continue;
            }
            addReplyErrorFormat(c,"%s", strerror(ret));
            return;
        } else {
#if BYTE_ORDER == BIG_ENDIAN
            old >>= 64 - 8*sz;
#endif
            addReplyLongLong(c, old);
            return;
        }
    }
    addReplyErrorFormat(c,"%s", strerror(EINVAL));
}

void mallctl_string(client *c, robj **argv, int argc) {
    int rret, wret;
    char *old;
    size_t sz = sizeof(old);
    /* for strings, it seems we need to first get the old value, before overriding it. */
    if ((rret=je_mallctl(argv[0]->ptr, &old, &sz, NULL, 0))) {
        /* return error unless this option is write only. */
        if (!(rret == EPERM && argc > 1)) {
            addReplyErrorFormat(c,"%s", strerror(rret));
            return;
        }
    }
    if(argc > 1) {
        char *val = argv[1]->ptr;
        char **valref = &val;
        if ((!strcmp(val,"VOID")))
            valref = NULL, sz = 0;
        wret = je_mallctl(argv[0]->ptr, NULL, 0, valref, sz);
    }
    if (!rret)
        addReplyBulkCString(c, old);
    else if (wret)
        addReplyErrorFormat(c,"%s", strerror(wret));
    else
        addReply(c, shared.ok);
}
#endif

/* =========================== Crash handling  ============================== */

void _serverAssert(const char *estr, const char *file, int line) {
    bugReportStart();
    serverLog(LL_WARNING,"=== ASSERTION FAILED ===");
    serverLog(LL_WARNING,"==> %s:%d '%s' is not true",file,line,estr);

    if (server.crashlog_enabled) {
#ifdef HAVE_BACKTRACE
        logStackTrace(NULL, 1);
#endif
        printCrashReport();
    }
    bugReportEnd(0, 0);
}

void serverLogObjectDebugInfo(const robj *o) {
    serverLog(LL_WARNING,"Object type: %d", o->type);
    serverLog(LL_WARNING,"Object encoding: %d", o->encoding);
    serverLog(LL_WARNING,"Object refcount: %d", o->refcount);
    if (o->type == OBJ_STRING && sdsEncodedObject(o)) {
        serverLog(LL_WARNING,"Object raw string len: %zu", sdslen(o->ptr));
        if (sdslen(o->ptr) < 4096) {
            sds repr = sdscatrepr(sdsempty(),o->ptr,sdslen(o->ptr));
            serverLog(LL_WARNING,"Object raw string content: %s", repr);
            sdsfree(repr);
        }
    } else if (o->type == OBJ_LIST) {
        serverLog(LL_WARNING,"List length: %d", (int) listTypeLength(o));
    } else if (o->type == OBJ_SET) {
        serverLog(LL_WARNING,"Set size: %d", (int) setTypeSize(o));
    } else if (o->type == OBJ_HASH) {
        serverLog(LL_WARNING,"Hash size: %d", (int) hashTypeLength(o));
    } else if (o->type == OBJ_ZSET) {
        serverLog(LL_WARNING,"Sorted set size: %d", (int) zsetLength(o));
        if (o->encoding == OBJ_ENCODING_SKIPLIST)
            serverLog(LL_WARNING,"Skiplist level: %d", (int) ((const zset*)o->ptr)->zsl->level);
    } else if (o->type == OBJ_STREAM) {
        serverLog(LL_WARNING,"Stream size: %d", (int) streamLength(o));
    }
}

void _serverAssertPrintObject(const robj *o) {
    bugReportStart();
    serverLog(LL_WARNING,"=== ASSERTION FAILED OBJECT CONTEXT ===");
    serverLogObjectDebugInfo(o);
}

void _serverAssertWithInfo(const robj *o, const char *estr, const char *file, int line) {
    if (o) _serverAssertPrintObject(o);
    _serverAssert(estr,file,line);
}

void _serverPanic(const char *file, int line, const char *msg, ...) {
    va_list ap;
    va_start(ap,msg);
    char fmtmsg[256];
    vsnprintf(fmtmsg,sizeof(fmtmsg),msg,ap);
    va_end(ap);

    bugReportStart();
    serverLog(LL_WARNING,"------------------------------------------------");
    serverLog(LL_WARNING,"!!! Software Failure. Press left mouse button to continue");
    serverLog(LL_WARNING,"Guru Meditation: %s #%s:%d",fmtmsg,file,line);

    if (server.crashlog_enabled) {
#ifdef HAVE_BACKTRACE
        logStackTrace(NULL, 1);
#endif
        printCrashReport();
    }
    bugReportEnd(0, 0);
}

void bugReportStart(void) {
    pthread_mutex_lock(&bug_report_start_mutex);
    if (bug_report_start == 0) {
        serverLogRaw(LL_WARNING|LL_RAW,
        "\n\n=== REDIS BUG REPORT START: Cut & paste starting from here ===\n");
        bug_report_start = 1;
    }
    pthread_mutex_unlock(&bug_report_start_mutex);
}

#ifdef HAVE_BACKTRACE
static void *getMcontextEip(ucontext_t *uc) {
#if defined(__APPLE__) && !defined(MAC_OS_X_VERSION_10_6)
    /* OSX < 10.6 */
    #if defined(__x86_64__)
    return (void*) uc->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void*) uc->uc_mcontext->__ss.__eip;
    #else
    return (void*) uc->uc_mcontext->__ss.__srr0;
    #endif
#elif defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
    /* OSX >= 10.6 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    return (void*) uc->uc_mcontext->__ss.__rip;
    #elif defined(__i386__)
    return (void*) uc->uc_mcontext->__ss.__eip;
    #else
    /* OSX ARM64 */
    return (void*) arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
    #endif
#elif defined(__linux__)
    /* Linux */
    #if defined(__i386__) || defined(__ILP32__)
    return (void*) uc->uc_mcontext.gregs[14]; /* Linux 32 */
    #elif defined(__X86_64__) || defined(__x86_64__)
    return (void*) uc->uc_mcontext.gregs[16]; /* Linux 64 */
    #elif defined(__ia64__) /* Linux IA64 */
    return (void*) uc->uc_mcontext.sc_ip;
    #elif defined(__arm__) /* Linux ARM */
    return (void*) uc->uc_mcontext.arm_pc;
    #elif defined(__aarch64__) /* Linux AArch64 */
    return (void*) uc->uc_mcontext.pc;
    #endif
#elif defined(__FreeBSD__)
    /* FreeBSD */
    #if defined(__i386__)
    return (void*) uc->uc_mcontext.mc_eip;
    #elif defined(__x86_64__)
    return (void*) uc->uc_mcontext.mc_rip;
    #endif
#elif defined(__OpenBSD__)
    /* OpenBSD */
    #if defined(__i386__)
    return (void*) uc->sc_eip;
    #elif defined(__x86_64__)
    return (void*) uc->sc_rip;
    #endif
#elif defined(__NetBSD__)
    #if defined(__i386__)
    return (void*) uc->uc_mcontext.__gregs[_REG_EIP];
    #elif defined(__x86_64__)
    return (void*) uc->uc_mcontext.__gregs[_REG_RIP];
    #endif
#elif defined(__DragonFly__)
    return (void*) uc->uc_mcontext.mc_rip;
#else
    return NULL;
#endif
}

void logStackContent(void **sp) {
    int i;
    for (i = 15; i >= 0; i--) {
        unsigned long addr = (unsigned long) sp+i;
        unsigned long val = (unsigned long) sp[i];

        if (sizeof(long) == 4)
            serverLog(LL_WARNING, "(%08lx) -> %08lx", addr, val);
        else
            serverLog(LL_WARNING, "(%016lx) -> %016lx", addr, val);
    }
}

/* Log dump of processor registers */
void logRegisters(ucontext_t *uc) {
    serverLog(LL_WARNING|LL_RAW, "\n------ REGISTERS ------\n");

/* OSX */
#if defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)
  /* OSX AMD64 */
    #if defined(_STRUCT_X86_THREAD_STATE64) && !defined(__i386__)
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCS :%016lx FS:%016lx  GS:%016lx",
        (unsigned long) uc->uc_mcontext->__ss.__rax,
        (unsigned long) uc->uc_mcontext->__ss.__rbx,
        (unsigned long) uc->uc_mcontext->__ss.__rcx,
        (unsigned long) uc->uc_mcontext->__ss.__rdx,
        (unsigned long) uc->uc_mcontext->__ss.__rdi,
        (unsigned long) uc->uc_mcontext->__ss.__rsi,
        (unsigned long) uc->uc_mcontext->__ss.__rbp,
        (unsigned long) uc->uc_mcontext->__ss.__rsp,
        (unsigned long) uc->uc_mcontext->__ss.__r8,
        (unsigned long) uc->uc_mcontext->__ss.__r9,
        (unsigned long) uc->uc_mcontext->__ss.__r10,
        (unsigned long) uc->uc_mcontext->__ss.__r11,
        (unsigned long) uc->uc_mcontext->__ss.__r12,
        (unsigned long) uc->uc_mcontext->__ss.__r13,
        (unsigned long) uc->uc_mcontext->__ss.__r14,
        (unsigned long) uc->uc_mcontext->__ss.__r15,
        (unsigned long) uc->uc_mcontext->__ss.__rip,
        (unsigned long) uc->uc_mcontext->__ss.__rflags,
        (unsigned long) uc->uc_mcontext->__ss.__cs,
        (unsigned long) uc->uc_mcontext->__ss.__fs,
        (unsigned long) uc->uc_mcontext->__ss.__gs
    );
    logStackContent((void**)uc->uc_mcontext->__ss.__rsp);
    #elif defined(__i386__)
    /* OSX x86 */
    serverLog(LL_WARNING,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS:%08lx  EFL:%08lx EIP:%08lx CS :%08lx\n"
    "DS:%08lx  ES:%08lx  FS :%08lx GS :%08lx",
        (unsigned long) uc->uc_mcontext->__ss.__eax,
        (unsigned long) uc->uc_mcontext->__ss.__ebx,
        (unsigned long) uc->uc_mcontext->__ss.__ecx,
        (unsigned long) uc->uc_mcontext->__ss.__edx,
        (unsigned long) uc->uc_mcontext->__ss.__edi,
        (unsigned long) uc->uc_mcontext->__ss.__esi,
        (unsigned long) uc->uc_mcontext->__ss.__ebp,
        (unsigned long) uc->uc_mcontext->__ss.__esp,
        (unsigned long) uc->uc_mcontext->__ss.__ss,
        (unsigned long) uc->uc_mcontext->__ss.__eflags,
        (unsigned long) uc->uc_mcontext->__ss.__eip,
        (unsigned long) uc->uc_mcontext->__ss.__cs,
        (unsigned long) uc->uc_mcontext->__ss.__ds,
        (unsigned long) uc->uc_mcontext->__ss.__es,
        (unsigned long) uc->uc_mcontext->__ss.__fs,
        (unsigned long) uc->uc_mcontext->__ss.__gs
    );
    logStackContent((void**)uc->uc_mcontext->__ss.__esp);
    #else
    /* OSX ARM64 */
    serverLog(LL_WARNING,
    "\n"
    "x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n"
    "x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n"
    "x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n"
    "x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n"
    "x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n"
    "x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n"
    "x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n"
    "x28:%016lx fp:%016lx lr:%016lx\n"
    "sp:%016lx pc:%016lx cpsr:%08lx\n",
        (unsigned long) uc->uc_mcontext->__ss.__x[0],
        (unsigned long) uc->uc_mcontext->__ss.__x[1],
        (unsigned long) uc->uc_mcontext->__ss.__x[2],
        (unsigned long) uc->uc_mcontext->__ss.__x[3],
        (unsigned long) uc->uc_mcontext->__ss.__x[4],
        (unsigned long) uc->uc_mcontext->__ss.__x[5],
        (unsigned long) uc->uc_mcontext->__ss.__x[6],
        (unsigned long) uc->uc_mcontext->__ss.__x[7],
        (unsigned long) uc->uc_mcontext->__ss.__x[8],
        (unsigned long) uc->uc_mcontext->__ss.__x[9],
        (unsigned long) uc->uc_mcontext->__ss.__x[10],
        (unsigned long) uc->uc_mcontext->__ss.__x[11],
        (unsigned long) uc->uc_mcontext->__ss.__x[12],
        (unsigned long) uc->uc_mcontext->__ss.__x[13],
        (unsigned long) uc->uc_mcontext->__ss.__x[14],
        (unsigned long) uc->uc_mcontext->__ss.__x[15],
        (unsigned long) uc->uc_mcontext->__ss.__x[16],
        (unsigned long) uc->uc_mcontext->__ss.__x[17],
        (unsigned long) uc->uc_mcontext->__ss.__x[18],
        (unsigned long) uc->uc_mcontext->__ss.__x[19],
        (unsigned long) uc->uc_mcontext->__ss.__x[20],
        (unsigned long) uc->uc_mcontext->__ss.__x[21],
        (unsigned long) uc->uc_mcontext->__ss.__x[22],
        (unsigned long) uc->uc_mcontext->__ss.__x[23],
        (unsigned long) uc->uc_mcontext->__ss.__x[24],
        (unsigned long) uc->uc_mcontext->__ss.__x[25],
        (unsigned long) uc->uc_mcontext->__ss.__x[26],
        (unsigned long) uc->uc_mcontext->__ss.__x[27],
        (unsigned long) uc->uc_mcontext->__ss.__x[28],
        (unsigned long) arm_thread_state64_get_fp(uc->uc_mcontext->__ss),
        (unsigned long) arm_thread_state64_get_lr(uc->uc_mcontext->__ss),
        (unsigned long) arm_thread_state64_get_sp(uc->uc_mcontext->__ss),
        (unsigned long) arm_thread_state64_get_pc(uc->uc_mcontext->__ss),
        (unsigned long) uc->uc_mcontext->__ss.__cpsr
    );
    logStackContent((void**) arm_thread_state64_get_sp(uc->uc_mcontext->__ss));
    #endif
/* Linux */
#elif defined(__linux__)
    /* Linux x86 */
    #if defined(__i386__) || defined(__ILP32__)
    serverLog(LL_WARNING,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx",
        (unsigned long) uc->uc_mcontext.gregs[11],
        (unsigned long) uc->uc_mcontext.gregs[8],
        (unsigned long) uc->uc_mcontext.gregs[10],
        (unsigned long) uc->uc_mcontext.gregs[9],
        (unsigned long) uc->uc_mcontext.gregs[4],
        (unsigned long) uc->uc_mcontext.gregs[5],
        (unsigned long) uc->uc_mcontext.gregs[6],
        (unsigned long) uc->uc_mcontext.gregs[7],
        (unsigned long) uc->uc_mcontext.gregs[18],
        (unsigned long) uc->uc_mcontext.gregs[17],
        (unsigned long) uc->uc_mcontext.gregs[14],
        (unsigned long) uc->uc_mcontext.gregs[15],
        (unsigned long) uc->uc_mcontext.gregs[3],
        (unsigned long) uc->uc_mcontext.gregs[2],
        (unsigned long) uc->uc_mcontext.gregs[1],
        (unsigned long) uc->uc_mcontext.gregs[0]
    );
    logStackContent((void**)uc->uc_mcontext.gregs[7]);
    #elif defined(__X86_64__) || defined(__x86_64__)
    /* Linux AMD64 */
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx",
        (unsigned long) uc->uc_mcontext.gregs[13],
        (unsigned long) uc->uc_mcontext.gregs[11],
        (unsigned long) uc->uc_mcontext.gregs[14],
        (unsigned long) uc->uc_mcontext.gregs[12],
        (unsigned long) uc->uc_mcontext.gregs[8],
        (unsigned long) uc->uc_mcontext.gregs[9],
        (unsigned long) uc->uc_mcontext.gregs[10],
        (unsigned long) uc->uc_mcontext.gregs[15],
        (unsigned long) uc->uc_mcontext.gregs[0],
        (unsigned long) uc->uc_mcontext.gregs[1],
        (unsigned long) uc->uc_mcontext.gregs[2],
        (unsigned long) uc->uc_mcontext.gregs[3],
        (unsigned long) uc->uc_mcontext.gregs[4],
        (unsigned long) uc->uc_mcontext.gregs[5],
        (unsigned long) uc->uc_mcontext.gregs[6],
        (unsigned long) uc->uc_mcontext.gregs[7],
        (unsigned long) uc->uc_mcontext.gregs[16],
        (unsigned long) uc->uc_mcontext.gregs[17],
        (unsigned long) uc->uc_mcontext.gregs[18]
    );
    logStackContent((void**)uc->uc_mcontext.gregs[15]);
    #elif defined(__aarch64__) /* Linux AArch64 */
    serverLog(LL_WARNING,
	      "\n"
	      "X18:%016lx X19:%016lx\nX20:%016lx X21:%016lx\n"
	      "X22:%016lx X23:%016lx\nX24:%016lx X25:%016lx\n"
	      "X26:%016lx X27:%016lx\nX28:%016lx X29:%016lx\n"
	      "X30:%016lx\n"
	      "pc:%016lx sp:%016lx\npstate:%016lx fault_address:%016lx\n",
	      (unsigned long) uc->uc_mcontext.regs[18],
	      (unsigned long) uc->uc_mcontext.regs[19],
	      (unsigned long) uc->uc_mcontext.regs[20],
	      (unsigned long) uc->uc_mcontext.regs[21],
	      (unsigned long) uc->uc_mcontext.regs[22],
	      (unsigned long) uc->uc_mcontext.regs[23],
	      (unsigned long) uc->uc_mcontext.regs[24],
	      (unsigned long) uc->uc_mcontext.regs[25],
	      (unsigned long) uc->uc_mcontext.regs[26],
	      (unsigned long) uc->uc_mcontext.regs[27],
	      (unsigned long) uc->uc_mcontext.regs[28],
	      (unsigned long) uc->uc_mcontext.regs[29],
	      (unsigned long) uc->uc_mcontext.regs[30],
	      (unsigned long) uc->uc_mcontext.pc,
	      (unsigned long) uc->uc_mcontext.sp,
	      (unsigned long) uc->uc_mcontext.pstate,
	      (unsigned long) uc->uc_mcontext.fault_address
		      );
	      logStackContent((void**)uc->uc_mcontext.sp);
    #elif defined(__arm__) /* Linux ARM */
    serverLog(LL_WARNING,
	      "\n"
	      "R10:%016lx R9 :%016lx\nR8 :%016lx R7 :%016lx\n"
	      "R6 :%016lx R5 :%016lx\nR4 :%016lx R3 :%016lx\n"
	      "R2 :%016lx R1 :%016lx\nR0 :%016lx EC :%016lx\n"
	      "fp: %016lx ip:%016lx\n",
	      "pc:%016lx sp:%016lx\ncpsr:%016lx fault_address:%016lx\n",
	      (unsigned long) uc->uc_mcontext.arm_r10,
	      (unsigned long) uc->uc_mcontext.arm_r9,
	      (unsigned long) uc->uc_mcontext.arm_r8,
	      (unsigned long) uc->uc_mcontext.arm_r7,
	      (unsigned long) uc->uc_mcontext.arm_r6,
	      (unsigned long) uc->uc_mcontext.arm_r5,
	      (unsigned long) uc->uc_mcontext.arm_r4,
	      (unsigned long) uc->uc_mcontext.arm_r3,
	      (unsigned long) uc->uc_mcontext.arm_r2,
	      (unsigned long) uc->uc_mcontext.arm_r1,
	      (unsigned long) uc->uc_mcontext.arm_r0,
	      (unsigned long) uc->uc_mcontext.error_code,
	      (unsigned long) uc->uc_mcontext.arm_fp,
	      (unsigned long) uc->uc_mcontext.arm_ip,
	      (unsigned long) uc->uc_mcontext.arm_pc,
	      (unsigned long) uc->uc_mcontext.arm_sp,
	      (unsigned long) uc->uc_mcontext.arm_cpsr,
	      (unsigned long) uc->uc_mcontext.fault_address
		      );
	      logStackContent((void**)uc->uc_mcontext.arm_sp);
    #endif
#elif defined(__FreeBSD__)
    #if defined(__x86_64__)
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx",
        (unsigned long) uc->uc_mcontext.mc_rax,
        (unsigned long) uc->uc_mcontext.mc_rbx,
        (unsigned long) uc->uc_mcontext.mc_rcx,
        (unsigned long) uc->uc_mcontext.mc_rdx,
        (unsigned long) uc->uc_mcontext.mc_rdi,
        (unsigned long) uc->uc_mcontext.mc_rsi,
        (unsigned long) uc->uc_mcontext.mc_rbp,
        (unsigned long) uc->uc_mcontext.mc_rsp,
        (unsigned long) uc->uc_mcontext.mc_r8,
        (unsigned long) uc->uc_mcontext.mc_r9,
        (unsigned long) uc->uc_mcontext.mc_r10,
        (unsigned long) uc->uc_mcontext.mc_r11,
        (unsigned long) uc->uc_mcontext.mc_r12,
        (unsigned long) uc->uc_mcontext.mc_r13,
        (unsigned long) uc->uc_mcontext.mc_r14,
        (unsigned long) uc->uc_mcontext.mc_r15,
        (unsigned long) uc->uc_mcontext.mc_rip,
        (unsigned long) uc->uc_mcontext.mc_rflags,
        (unsigned long) uc->uc_mcontext.mc_cs
    );
    logStackContent((void**)uc->uc_mcontext.mc_rsp);
    #elif defined(__i386__)
    serverLog(LL_WARNING,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx",
        (unsigned long) uc->uc_mcontext.mc_eax,
        (unsigned long) uc->uc_mcontext.mc_ebx,
        (unsigned long) uc->uc_mcontext.mc_ebx,
        (unsigned long) uc->uc_mcontext.mc_edx,
        (unsigned long) uc->uc_mcontext.mc_edi,
        (unsigned long) uc->uc_mcontext.mc_esi,
        (unsigned long) uc->uc_mcontext.mc_ebp,
        (unsigned long) uc->uc_mcontext.mc_esp,
        (unsigned long) uc->uc_mcontext.mc_ss,
        (unsigned long) uc->uc_mcontext.mc_eflags,
        (unsigned long) uc->uc_mcontext.mc_eip,
        (unsigned long) uc->uc_mcontext.mc_cs,
        (unsigned long) uc->uc_mcontext.mc_es,
        (unsigned long) uc->uc_mcontext.mc_fs,
        (unsigned long) uc->uc_mcontext.mc_gs
    );
    logStackContent((void**)uc->uc_mcontext.mc_esp);
    #endif
#elif defined(__OpenBSD__)
    #if defined(__x86_64__)
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx",
        (unsigned long) uc->sc_rax,
        (unsigned long) uc->sc_rbx,
        (unsigned long) uc->sc_rcx,
        (unsigned long) uc->sc_rdx,
        (unsigned long) uc->sc_rdi,
        (unsigned long) uc->sc_rsi,
        (unsigned long) uc->sc_rbp,
        (unsigned long) uc->sc_rsp,
        (unsigned long) uc->sc_r8,
        (unsigned long) uc->sc_r9,
        (unsigned long) uc->sc_r10,
        (unsigned long) uc->sc_r11,
        (unsigned long) uc->sc_r12,
        (unsigned long) uc->sc_r13,
        (unsigned long) uc->sc_r14,
        (unsigned long) uc->sc_r15,
        (unsigned long) uc->sc_rip,
        (unsigned long) uc->sc_rflags,
        (unsigned long) uc->sc_cs
    );
    logStackContent((void**)uc->sc_rsp);
    #elif defined(__i386__)
    serverLog(LL_WARNING,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx",
        (unsigned long) uc->sc_eax,
        (unsigned long) uc->sc_ebx,
        (unsigned long) uc->sc_ebx,
        (unsigned long) uc->sc_edx,
        (unsigned long) uc->sc_edi,
        (unsigned long) uc->sc_esi,
        (unsigned long) uc->sc_ebp,
        (unsigned long) uc->sc_esp,
        (unsigned long) uc->sc_ss,
        (unsigned long) uc->sc_eflags,
        (unsigned long) uc->sc_eip,
        (unsigned long) uc->sc_cs,
        (unsigned long) uc->sc_es,
        (unsigned long) uc->sc_fs,
        (unsigned long) uc->sc_gs
    );
    logStackContent((void**)uc->sc_esp);
    #endif
#elif defined(__NetBSD__)
    #if defined(__x86_64__)
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx",
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RAX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RBX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RCX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RDX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RDI],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RSI],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RBP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RSP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R8],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R9],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R10],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R11],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R12],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R13],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R14],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_R15],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RIP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_RFLAGS],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_CS]
    );
    logStackContent((void**)uc->uc_mcontext.__gregs[_REG_RSP]);
    #elif defined(__i386__)
    serverLog(LL_WARNING,
    "\n"
    "EAX:%08lx EBX:%08lx ECX:%08lx EDX:%08lx\n"
    "EDI:%08lx ESI:%08lx EBP:%08lx ESP:%08lx\n"
    "SS :%08lx EFL:%08lx EIP:%08lx CS:%08lx\n"
    "DS :%08lx ES :%08lx FS :%08lx GS:%08lx",
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EAX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EBX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EDX],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EDI],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_ESI],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EBP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_ESP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_SS],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EFLAGS],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_EIP],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_CS],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_ES],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_FS],
        (unsigned long) uc->uc_mcontext.__gregs[_REG_GS]
    );
    #endif
#elif defined(__DragonFly__)
    serverLog(LL_WARNING,
    "\n"
    "RAX:%016lx RBX:%016lx\nRCX:%016lx RDX:%016lx\n"
    "RDI:%016lx RSI:%016lx\nRBP:%016lx RSP:%016lx\n"
    "R8 :%016lx R9 :%016lx\nR10:%016lx R11:%016lx\n"
    "R12:%016lx R13:%016lx\nR14:%016lx R15:%016lx\n"
    "RIP:%016lx EFL:%016lx\nCSGSFS:%016lx",
        (unsigned long) uc->uc_mcontext.mc_rax,
        (unsigned long) uc->uc_mcontext.mc_rbx,
        (unsigned long) uc->uc_mcontext.mc_rcx,
        (unsigned long) uc->uc_mcontext.mc_rdx,
        (unsigned long) uc->uc_mcontext.mc_rdi,
        (unsigned long) uc->uc_mcontext.mc_rsi,
        (unsigned long) uc->uc_mcontext.mc_rbp,
        (unsigned long) uc->uc_mcontext.mc_rsp,
        (unsigned long) uc->uc_mcontext.mc_r8,
        (unsigned long) uc->uc_mcontext.mc_r9,
        (unsigned long) uc->uc_mcontext.mc_r10,
        (unsigned long) uc->uc_mcontext.mc_r11,
        (unsigned long) uc->uc_mcontext.mc_r12,
        (unsigned long) uc->uc_mcontext.mc_r13,
        (unsigned long) uc->uc_mcontext.mc_r14,
        (unsigned long) uc->uc_mcontext.mc_r15,
        (unsigned long) uc->uc_mcontext.mc_rip,
        (unsigned long) uc->uc_mcontext.mc_rflags,
        (unsigned long) uc->uc_mcontext.mc_cs
    );
    logStackContent((void**)uc->uc_mcontext.mc_rsp);
#else
    serverLog(LL_WARNING,
        "  Dumping of registers not supported for this OS/arch");
#endif
}

#endif /* HAVE_BACKTRACE */

/* Return a file descriptor to write directly to the Redis log with the
 * write(2) syscall, that can be used in critical sections of the code
 * where the rest of Redis can't be trusted (for example during the memory
 * test) or when an API call requires a raw fd.
 *
 * Close it with closeDirectLogFiledes(). */
int openDirectLogFiledes(void) {
    int log_to_stdout = server.logfile[0] == '\0';
    int fd = log_to_stdout ?
        STDOUT_FILENO :
        open(server.logfile, O_APPEND|O_CREAT|O_WRONLY, 0644);
    return fd;
}

/* Used to close what closeDirectLogFiledes() returns. */
void closeDirectLogFiledes(int fd) {
    int log_to_stdout = server.logfile[0] == '\0';
    if (!log_to_stdout) close(fd);
}

#ifdef HAVE_BACKTRACE

/* Logs the stack trace using the backtrace() call. This function is designed
 * to be called from signal handlers safely.
 * The eip argument is optional (can take NULL).
 * The uplevel argument indicates how many of the calling functions to skip.
 */
void logStackTrace(void *eip, int uplevel) {
    void *trace[100];
    int trace_size = 0, fd = openDirectLogFiledes();
    char *msg;
    uplevel++; /* skip this function */

    if (fd == -1) return; /* If we can't log there is anything to do. */

    /* Get the stack trace first! */
    trace_size = backtrace(trace, 100);

    msg = "\n------ STACK TRACE ------\n";
    if (write(fd,msg,strlen(msg)) == -1) {/* Avoid warning. */};

    if (eip) {
        /* Write EIP to the log file*/
        msg = "EIP:\n";
        if (write(fd,msg,strlen(msg)) == -1) {/* Avoid warning. */};
        backtrace_symbols_fd(&eip, 1, fd);
    }

    /* Write symbols to log file */
    msg = "\nBacktrace:\n";
    if (write(fd,msg,strlen(msg)) == -1) {/* Avoid warning. */};
    backtrace_symbols_fd(trace+uplevel, trace_size-uplevel, fd);

    /* Cleanup */
    closeDirectLogFiledes(fd);
}

#endif /* HAVE_BACKTRACE */

/* Log global server info */
void logServerInfo(void) {
    serverLogRaw(LL_WARNING|LL_RAW, "\n------ INFO OUTPUT ------\n");
    serverLogRaw(LL_WARNING|LL_RAW, "\n------ CLIENT LIST OUTPUT ------\n");
}

/* Log modules info. Something we wanna do last since we fear it may crash. */

/* Log information about the "current" client, that is, the client that is
 * currently being served by Redis. May be NULL if Redis is not serving a
 * client right now. */

#if defined(HAVE_PROC_MAPS)

#define MEMTEST_MAX_REGIONS 128

/* A non destructive memory test executed during segfault. */
int memtest_test_linux_anonymous_maps(void) {
    FILE *fp;
    char line[1024];
    char logbuf[1024];
    size_t start_addr, end_addr, size;
    size_t start_vect[MEMTEST_MAX_REGIONS];
    size_t size_vect[MEMTEST_MAX_REGIONS];
    int regions = 0, j;

    int fd = openDirectLogFiledes();
    if (!fd) return 0;

    fp = fopen("/proc/self/maps","r");
    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        char *start, *end, *p = line;

        start = p;
        p = strchr(p,'-');
        if (!p) continue;
        *p++ = '\0';
        end = p;
        p = strchr(p,' ');
        if (!p) continue;
        *p++ = '\0';
        if (strstr(p,"stack") ||
            strstr(p,"vdso") ||
            strstr(p,"vsyscall")) continue;
        if (!strstr(p,"00:00")) continue;
        if (!strstr(p,"rw")) continue;

        start_addr = strtoul(start,NULL,16);
        end_addr = strtoul(end,NULL,16);
        size = end_addr-start_addr;

        start_vect[regions] = start_addr;
        size_vect[regions] = size;
        snprintf(logbuf,sizeof(logbuf),
            "*** Preparing to test memory region %lx (%lu bytes)\n",
                (unsigned long) start_vect[regions],
                (unsigned long) size_vect[regions]);
        if (write(fd,logbuf,strlen(logbuf)) == -1) { /* Nothing to do. */ }
        regions++;
    }

    int errors = 0;
    for (j = 0; j < regions; j++) {
        if (write(fd,".",1) == -1) { /* Nothing to do. */ }
        errors += memtest_preserving_test((void*)start_vect[j],size_vect[j],1);
        if (write(fd, errors ? "E" : "O",1) == -1) { /* Nothing to do. */ }
    }
    if (write(fd,"\n",1) == -1) { /* Nothing to do. */ }

    /* NOTE: It is very important to close the file descriptor only now
     * because closing it before may result into unmapping of some memory
     * region that we are testing. */
    fclose(fp);
    closeDirectLogFiledes(fd);
    return errors;
}
#endif /* HAVE_PROC_MAPS */

static void killMainThread(void) {
    int err;
    if (pthread_self() != server.main_thread_id && pthread_cancel(server.main_thread_id) == 0) {
        if ((err = pthread_join(server.main_thread_id,NULL)) != 0) {
            serverLog(LL_WARNING, "main thread can not be joined: %s", strerror(err));
        } else {
            serverLog(LL_WARNING, "main thread terminated");
        }
    }
}

/* Kill the running threads (other than current) in an unclean way. This function
 * should be used only when it's critical to stop the threads for some reason.
 * Currently Redis does this only on crash (for instance on SIGSEGV) in order
 * to perform a fast memory check without other threads messing with memory. */
void killThreads(void) {
    killMainThread();
    bioKillThreads();
    // killIOThreads();
}

void doFastMemoryTest(void) {
#if defined(HAVE_PROC_MAPS)
    if (server.memcheck_enabled) {
        /* Test memory */
        serverLogRaw(LL_WARNING|LL_RAW, "\n------ FAST MEMORY TEST ------\n");
        killThreads();
        if (memtest_test_linux_anonymous_maps()) {
            serverLogRaw(LL_WARNING|LL_RAW,
                "!!! MEMORY ERROR DETECTED! Check your memory ASAP !!!\n");
        } else {
            serverLogRaw(LL_WARNING|LL_RAW,
                "Fast memory test PASSED, however your memory can still be broken. Please run a memory test for several hours if possible.\n");
        }
    }
#endif /* HAVE_PROC_MAPS */
}

#ifdef HAVE_BACKTRACE
#include <dlfcn.h>

/* Scans the (assumed) x86 code starting at addr, for a max of `len`
 * bytes, searching for E8 (callq) opcodes, and dumping the symbols
 * and the call offset if they appear to be valid. */
void dumpX86Calls(void *addr, size_t len) {
    size_t j;
    unsigned char *p = addr;
    Dl_info info;
    /* Hash table to best-effort avoid printing the same symbol
     * multiple times. */
    unsigned long ht[256] = {0};

    if (len < 5) return;
    for (j = 0; j < len-4; j++) {
        if (p[j] != 0xE8) continue; /* Not an E8 CALL opcode. */
        unsigned long target = (unsigned long)addr+j+5;
        target += *((int32_t*)(p+j+1));
        if (dladdr((void*)target, &info) != 0 && info.dli_sname != NULL) {
            if (ht[target&0xff] != target) {
                printf("Function at 0x%lx is %s\n",target,info.dli_sname);
                ht[target&0xff] = target;
            }
            j += 4; /* Skip the 32 bit immediate. */
        }
    }
}

void dumpCodeAroundEIP(void *eip) {
    Dl_info info;
    if (dladdr(eip, &info) != 0) {
        serverLog(LL_WARNING|LL_RAW,
            "\n------ DUMPING CODE AROUND EIP ------\n"
            "Symbol: %s (base: %p)\n"
            "Module: %s (base %p)\n"
            "$ xxd -r -p /tmp/dump.hex /tmp/dump.bin\n"
            "$ objdump --adjust-vma=%p -D -b binary -m i386:x86-64 /tmp/dump.bin\n"
            "------\n",
            info.dli_sname, info.dli_saddr, info.dli_fname, info.dli_fbase,
            info.dli_saddr);
        size_t len = (long)eip - (long)info.dli_saddr;
        unsigned long sz = sysconf(_SC_PAGESIZE);
        if (len < 1<<13) { /* we don't have functions over 8k (verified) */
            /* Find the address of the next page, which is our "safety"
             * limit when dumping. Then try to dump just 128 bytes more
             * than EIP if there is room, or stop sooner. */
            void *base = (void *)info.dli_saddr;
            unsigned long next = ((unsigned long)eip + sz) & ~(sz-1);
            unsigned long end = (unsigned long)eip + 128;
            if (end > next) end = next;
            len = end - (unsigned long)base;
            serverLogHexDump(LL_WARNING, "dump of function",
                base, len);
            dumpX86Calls(base, len);
        }
    }
}
#endif

void sigsegvHandler(int sig, siginfo_t *info, void *secret) {
    UNUSED(secret);
    UNUSED(info);

    bugReportStart();
    serverLog(LL_WARNING,
        "Redis crashed by signal: %d", sig);
    if (sig == SIGSEGV || sig == SIGBUS) {
        serverLog(LL_WARNING,
        "Accessing address: %p", (void*)info->si_addr);
    }
    if (info->si_pid != -1) {
        serverLog(LL_WARNING, "Killed by PID: %d, UID: %d", info->si_pid, info->si_uid);
    }

#ifdef HAVE_BACKTRACE
    ucontext_t *uc = (ucontext_t*) secret;
    void *eip = getMcontextEip(uc);
    if (eip != NULL) {
        serverLog(LL_WARNING,
        "Crashed running the instruction at: %p", eip);
    }

    logStackTrace(getMcontextEip(uc), 1);

    logRegisters(uc);
#endif

    printCrashReport();

#ifdef HAVE_BACKTRACE
    if (eip != NULL)
        dumpCodeAroundEIP(eip);
#endif

    bugReportEnd(1, sig);
}

void printCrashReport(void) {
    /* Log INFO and CLIENT LIST */
    logServerInfo();

    /* Log the current client */
    // logCurrentClient();

    /* Log modules info. Something we wanna do last since we fear it may crash. */
    // logModulesInfo();

    /* Run memory test in case the crash was triggered by memory corruption. */
    doFastMemoryTest();
}

void bugReportEnd(int killViaSignal, int sig) {
    struct sigaction act;

    serverLogRaw(LL_WARNING|LL_RAW,
"\n=== REDIS BUG REPORT END. Make sure to include from START to END. ===\n\n"
"       Please report the crash by opening an issue on github:\n\n"
"           http://github.com/redis/redis/issues\n\n"
"  Suspect RAM error? Use redis-server --test-memory to verify it.\n\n"
);

    /* free(messages); Don't call free() with possibly corrupted memory. */
    // if (server.daemonize && server.supervised == 0) unlink(server.pidfile);

    if (!killViaSignal) {
        if (server.use_exit_on_panic)
            exit(1);
        abort();
    }

    /* Make sure we exit with the right signal at the end. So for instance
     * the core will be dumped if enabled. */
    sigemptyset (&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    act.sa_handler = SIG_DFL;
    sigaction (sig, &act, NULL);
    kill(getpid(),sig);
}

/* ==================== Logging functions for debugging ===================== */

void serverLogHexDump(int level, char *descr, void *value, size_t len) {
    char buf[65], *b;
    unsigned char *v = value;
    char charset[] = "0123456789abcdef";

    serverLog(level,"%s (hexdump of %zu bytes):", descr, len);
    b = buf;
    while(len) {
        b[0] = charset[(*v)>>4];
        b[1] = charset[(*v)&0xf];
        b[2] = '\0';
        b += 2;
        len--;
        v++;
        if (b-buf == 64 || len == 0) {
            serverLogRaw(level|LL_RAW,buf);
            b = buf;
        }
    }
    serverLogRaw(level|LL_RAW,"\n");
}

/* =========================== Software Watchdog ============================ */
#include <sys/time.h>

void watchdogSignalHandler(int sig, siginfo_t *info, void *secret) {
#ifdef HAVE_BACKTRACE
    ucontext_t *uc = (ucontext_t*) secret;
#else
    (void)secret;
#endif
    UNUSED(info);
    UNUSED(sig);

    serverLogFromHandler(LL_WARNING,"\n--- WATCHDOG TIMER EXPIRED ---");
#ifdef HAVE_BACKTRACE
    logStackTrace(getMcontextEip(uc), 1);
#else
    serverLogFromHandler(LL_WARNING,"Sorry: no support for backtrace().");
#endif
    serverLogFromHandler(LL_WARNING,"--------\n");
}

/* Schedule a SIGALRM delivery after the specified period in milliseconds.
 * If a timer is already scheduled, this function will re-schedule it to the
 * specified time. If period is 0 the current timer is disabled. */
void watchdogScheduleSignal(int period) {
    struct itimerval it;

    /* Will stop the timer if period is 0. */
    it.it_value.tv_sec = period/1000;
    it.it_value.tv_usec = (period%1000)*1000;
    /* Don't automatically restart. */
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
}

/* Enable the software watchdog with the specified period in milliseconds. */
void enableWatchdog(int period) {
    int min_period;

    if (server.watchdog_period == 0) {
        struct sigaction act;

        /* Watchdog was actually disabled, so we have to setup the signal
         * handler. */
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_SIGINFO;
        act.sa_sigaction = watchdogSignalHandler;
        sigaction(SIGALRM, &act, NULL);
    }
    /* If the configured period is smaller than twice the timer period, it is
     * too short for the software watchdog to work reliably. Fix it now
     * if needed. */
    min_period = (1000/server.hz)*2;
    if (period < min_period) period = min_period;
    watchdogScheduleSignal(period); /* Adjust the current timer. */
    server.watchdog_period = period;
}

/* Disable the software watchdog. */
void disableWatchdog(void) {
    struct sigaction act;
    if (server.watchdog_period == 0) return; /* Already disabled. */
    watchdogScheduleSignal(0); /* Stop the current timer. */

    /* Set the signal handler to SIG_IGN, this will also remove pending
     * signals from the queue. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &act, NULL);
    server.watchdog_period = 0;
}

/* Positive input is sleep time in microseconds. Negative input is fractions
 * of microseconds, i.e. -10 means 100 nanoseconds. */
void debugDelay(int usec) {
    /* Since even the shortest sleep results in context switch and system call,
     * the way we achive short sleeps is by statistically sleeping less often. */
    if (usec < 0) usec = (rand() % -usec) == 0 ? 1: 0;
    if (usec) usleep(usec);
}
