#!/bin/bash

os=`uname`

target="vfdposix"
include_platform_dir=""

if [[ "Linux" == "$os" ]]
then
	target="lib$target.so"
	include_platform_dir="linux"
elif [[ "Darwin" == "$os" ]]
then
	target="lib$target.dylib"
	include_platform_dir="darwin"
else
	echo "unsupported platform $os"
	exit 1
fi

rm -f "$target"

LIBAE="../../../../submodules/libae/src"

GENERATED_PATH="../c-generated"
if [ "$VPROXY_BUILD_GRAAL_NATIVE_IMAGE" == "true" ]; then
    GENERATED_PATH="${GENERATED_PATH}-graal"
    GCC_OPTS="$GCC_OPTS -DPNI_GRAAL=1"
fi

gcc -std=gnu99 -O2 \
    $GCC_OPTS \
    -I "$LIBAE" \
    -I "$GENERATED_PATH" \
    -L . \
    -shared -Werror -lc -lpthread -lpni -fPIC \
    io_vproxy_vfd_posix_GeneralPosix.c $LIBAE/ae.c $LIBAE/anet.c $LIBAE/zmalloc.c $LIBAE/monotonic.c \
    -o "$target"
