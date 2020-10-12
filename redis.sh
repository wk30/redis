#!/bin/bash

files=(
adlist.h adlist.c
ae.h ae.c ae_epoll.c ae_evport.c ae_kqueue.c ae_select.c
anet.h anet.c
atomicvar.h
bio.c bio.h
config.h
connection.h connection.c connhelpers.h
crc16.c crc64.c crcspeed.c crc16_slottable.h crc64.h crcspeed.h
db.c
debugmacro.h
debug.c
defrag.c #TODO
dict.h dict.c
endianconv.c endianconv.h
evict.c #TODO
fmacros.h
geo.h geo.c geohash.h geohash.c geohash_helper.c geohash_helper.h
hyperloglog.c
intset.c intset.h
latency.h latency.c
lazyfree.c
listpack.h listpack.c listpack_malloc.h
localtime.c
lolwut.h lolwut.c lolwut5.c lolwut6.c
lzf.h lzfP.h lzf_c.c lzf_d.c
memtest.c
monotonic.h monotonic.c
object.c
pqsort.c pqsort.h
quicklist.h quicklist.c
rand.c rand.h
rax.h rax.c rax_malloc.h
redis-benchmark.c
redisassert.h
# release.c release.h
rio.c rio.h
sds.c sds.h sdsalloc.h
server.c server.h
setcpuaffinity.c
setproctitle.c
sha1.c sha1.h sha256.c sha256.h
siphash.c
solarisfixes.h
sort.c
sparkline.h sparkline.c
stream.h
syncio.c
t_stream.c t_hash.c t_list.c t_set.c t_string.c t_zset.c
testhelp.h
tls.c #TODO
util.c util.h
ziplist.c ziplist.h
zipmap.c zipmap.h
zmalloc.c zmalloc.h)

path=""
for f in ${files[@]}; do
    path+="--path src/$f "
done
path+="--path .gitignore"

git filter-repo --path src/Makefile $path --force
