module io.vproxy.base {
    requires jdk.unsupported;
    requires kotlin.stdlib;
    requires kotlinx.coroutines.core.jvm;

    requires transitive io.vproxy.dep;

    exports io.vproxy.base;
    exports io.vproxy.base.component.check;
    exports io.vproxy.base.component.elgroup;
    exports io.vproxy.base.component.elgroup.dummy;
    exports io.vproxy.base.component.svrgroup;
    exports io.vproxy.base.connection;
    exports io.vproxy.base.connection.util;
    exports io.vproxy.base.dhcp;
    exports io.vproxy.base.dhcp.options;
    exports io.vproxy.base.dns;
    exports io.vproxy.base.dns.dnsserverlistgetter;
    exports io.vproxy.base.dns.rdata;
    exports io.vproxy.base.http;
    exports io.vproxy.base.http.connect;
    exports io.vproxy.base.processor;
    exports io.vproxy.base.processor.common;
    exports io.vproxy.base.processor.dubbo;
    exports io.vproxy.base.processor.http;
    exports io.vproxy.base.processor.http1;
    exports io.vproxy.base.processor.http1.builder;
    exports io.vproxy.base.processor.http1.entity;
    exports io.vproxy.base.processor.httpbin;
    exports io.vproxy.base.processor.httpbin.entity;
    exports io.vproxy.base.processor.httpbin.frame;
    exports io.vproxy.base.processor.httpbin.hpack;
    exports io.vproxy.base.prometheus;
    exports io.vproxy.base.protocol;
    exports io.vproxy.base.redis;
    exports io.vproxy.base.redis.application;
    exports io.vproxy.base.redis.entity;
    exports io.vproxy.base.selector;
    exports io.vproxy.base.selector.wrap;
    exports io.vproxy.base.selector.wrap.arqudp;
    exports io.vproxy.base.selector.wrap.blocking;
    exports io.vproxy.base.selector.wrap.file;
    exports io.vproxy.base.selector.wrap.h2streamed;
    exports io.vproxy.base.selector.wrap.kcp;
    exports io.vproxy.base.selector.wrap.kcp.mock;
    exports io.vproxy.base.selector.wrap.streamed;
    exports io.vproxy.base.selector.wrap.udp;
    exports io.vproxy.base.socks;
    exports io.vproxy.base.util;
    exports io.vproxy.base.util.anno;
    exports io.vproxy.base.util.bitwise;
    exports io.vproxy.base.util.bytearray;
    exports io.vproxy.base.util.callback;
    exports io.vproxy.base.util.codec;
    exports io.vproxy.base.util.coll;
    exports io.vproxy.base.util.crypto;
    exports io.vproxy.base.util.direct;
    exports io.vproxy.base.util.display;
    exports io.vproxy.base.util.exception;
    exports io.vproxy.base.util.file;
    exports io.vproxy.base.util.functional;
    exports io.vproxy.base.util.io;
    exports io.vproxy.base.util.kt;
    exports io.vproxy.base.util.misc;
    exports io.vproxy.base.util.net;
    exports io.vproxy.base.util.nio;
    exports io.vproxy.base.util.objectpool;
    exports io.vproxy.base.util.promise;
    exports io.vproxy.base.util.ratelimit;
    exports io.vproxy.base.util.ringbuffer;
    exports io.vproxy.base.util.ringbuffer.ssl;
    exports io.vproxy.base.util.thread;
    exports io.vproxy.base.util.time;
    exports io.vproxy.base.util.time.impl;
    exports io.vproxy.base.util.unsafe;
    exports io.vproxy.base.util.web;
    exports io.vproxy.vfd;
    exports io.vproxy.vfd.abs;
    exports io.vproxy.vfd.jdk;
    exports io.vproxy.vfd.posix;
    exports io.vproxy.vfd.windows;
    exports io.vproxy.vmirror;
    exports io.vproxy.vpacket;
    exports io.vproxy.vpacket.conntrack;
    exports io.vproxy.vpacket.conntrack.tcp;
    exports io.vproxy.vpacket.conntrack.udp;
    exports io.vproxy.vpacket.tuples;
    exports io.vproxy.xdp;

    uses io.vproxy.vfd.FDs;
    uses io.vproxy.base.processor.ProcessorRegistry;
}
