package io.vproxy.app.app.cmd

import io.vproxy.app.app.cmd.handle.param.*
import io.vproxy.app.app.cmd.handle.resource.*
import io.vproxy.base.util.display.TableBuilder
import java.util.stream.Collectors

@Suppress("NestedLambdaShadowedImplicitParameter")
class ModuleCommands private constructor() : Commands() {
  companion object {
    val Instance = ModuleCommands()
  }

  init {
    val it = AddHelper(resources)
    it + Res(ResourceType.tl) {
      it + ResAct(
        relation = ResourceType.tl,
        action = ActType.add,
        params = {
          it + ResActParam(Param.addr, required) { AddrHandle.check(it) }
          it + ResActParam(Param.ups, required)
          it + ResActParam(Param.aelg)
          it + ResActParam(Param.elg)
          it + ResActParam(Param.inbuffersize) { InBufferSizeHandle.check(it) }
          it + ResActParam(Param.outbuffersize) { OutBufferSizeHandle.check(it) }
          it + ResActParam(Param.timeout) { TimeoutHandle.check(it) }
          it + ResActParam(Param.protocol)
          it + ResActParam(Param.ck)
          it + ResActParam(Param.secg)
        },
        exec = execUpdate { TcpLBHandle.add(it) },
      )
      it + ResAct(
        relation = ResourceType.tl,
        ActType.list,
      ) {
        val tlNames = TcpLBHandle.names()
        CmdResult(tlNames, tlNames, utilJoinList(tlNames))
      }
      it + ResAct(
        relation = ResourceType.tl,
        action = ActType.listdetail,
      ) {
        val tlRefList = TcpLBHandle.details()
        val tlRefStrList = tlRefList.stream().map { it.toString() }.collect(Collectors.toList())
        CmdResult(tlRefList, tlRefStrList, utilJoinList(tlRefList))
      }
      it + ResAct(
        relation = ResourceType.tl,
        action = ActType.update,
        params = {
          it + ResActParam(Param.inbuffersize) { InBufferSizeHandle.check(it) }
          it + ResActParam(Param.outbuffersize) { OutBufferSizeHandle.check(it) }
          it + ResActParam(Param.timeout) { TimeoutHandle.check(it) }
          it + ResActParam(Param.ck)
          it + ResActParam(Param.secg)
        },
        exec = execUpdate { TcpLBHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.tl,
        action = ActType.remove,
        exec = execUpdate { TcpLBHandle.remove(it) }
      )
    }
    it + Res(ResourceType.socks5) {
      it + ResAct(
        relation = ResourceType.socks5,
        action = ActType.add,
        params = {
          it + ResActParam(Param.addr, required) { AddrHandle.check(it) }
          it + ResActParam(Param.ups, required)
          it + ResActParam(Param.aelg)
          it + ResActParam(Param.elg)
          it + ResActParam(Param.inbuffersize) { InBufferSizeHandle.check(it) }
          it + ResActParam(Param.outbuffersize) { OutBufferSizeHandle.check(it) }
          it + ResActParam(Param.timeout) { TimeoutHandle.check(it) }
          it + ResActParam(Param.secg)
        },
        flags = {
          it + ResActFlag(Flag.allownonbackend)
          it + ResActFlag(Flag.denynonbackend)
        },
        exec = execUpdate { Socks5ServerHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.socks5,
        action = ActType.list
      ) {
        val socks5Names = Socks5ServerHandle.names()
        CmdResult(socks5Names, socks5Names, utilJoinList(socks5Names))
      }
      it + ResAct(
        relation = ResourceType.socks5,
        action = ActType.listdetail
      ) {
        val socks5RefList = Socks5ServerHandle.details()
        val socks5RefStrList = socks5RefList.stream().map { it.toString() }.collect(Collectors.toList())
        CmdResult(socks5RefList, socks5RefStrList, utilJoinList(socks5RefList))
      }
      it + ResAct(
        relation = ResourceType.socks5,
        action = ActType.update,
        params = {
          it + ResActParam(Param.inbuffersize) { InBufferSizeHandle.check(it) }
          it + ResActParam(Param.outbuffersize) { OutBufferSizeHandle.check(it) }
          it + ResActParam(Param.timeout) { TimeoutHandle.check(it) }
          it + ResActParam(Param.secg)
        },
        flags = {
          it + ResActFlag(Flag.allownonbackend)
          it + ResActFlag(Flag.denynonbackend)
        },
        exec = execUpdate { Socks5ServerHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.socks5,
        action = ActType.remove,
        exec = execUpdate { Socks5ServerHandle.remove(it) }
      )
    }
    it + Res(ResourceType.dns) {
      it + ResAct(
        relation = ResourceType.dns,
        action = ActType.add,
        params = {
          it + ResActParam(Param.addr, required) { AddrHandle.check(it) }
          it + ResActParam(Param.ups, required)
          it + ResActParam(Param.elg)
          it + ResActParam(Param.ttl) { TTLHandle.check(it) }
          it + ResActParam(Param.secg)
        },
        exec = execUpdate { DNSServerHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.dns,
        action = ActType.list,
        exec = {
          val dnsServerNames = DNSServerHandle.names()
          CmdResult(dnsServerNames, dnsServerNames, utilJoinList(dnsServerNames))
        }
      )
      it + ResAct(
        relation = ResourceType.dns,
        action = ActType.listdetail,
        exec = {
          val dnsServerRefList = DNSServerHandle.details()
          val dnsServerRefStrList = dnsServerRefList.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(dnsServerRefStrList, dnsServerRefStrList, utilJoinList(dnsServerRefList))
        }
      )
      it + ResAct(
        relation = ResourceType.dns,
        action = ActType.update,
        params = {
          it + ResActParam(Param.ttl) { TTLHandle.check(it) }
          it + ResActParam(Param.secg)
        },
        exec = execUpdate { DNSServerHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.dns,
        action = ActType.remove,
        exec = execUpdate { DNSServerHandle.remove(it) }
      )
    }
    it + Res(ResourceType.elg) {
      it + ResAct(
        relation = ResourceType.elg,
        action = ActType.add,
        params = {
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        exec = execUpdate { EventLoopGroupHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.elg,
        action = ActType.list,
        exec = {
          val elgNames = EventLoopGroupHandle.names()
          CmdResult(elgNames, elgNames, utilJoinList(elgNames))
        }
      )
      it + ResAct(
        relation = ResourceType.elg,
        action = ActType.listdetail,
        exec = {
          val elgs = EventLoopGroupHandle.details()
          val elgStrs = elgs.stream().map { it.toString() }
            .collect(Collectors.toList())
          CmdResult(elgs, elgStrs, utilJoinList(elgs))
        }
      )
      it + ResAct(
        relation = ResourceType.elg,
        action = ActType.remove,
        check = { EventLoopGroupHandle.preRemoveCheck(it) },
        exec = execUpdate { EventLoopGroupHandle.remvoe(it) }
      )
    }
    it + Res(ResourceType.ups) {
      it + ResAct(
        relation = ResourceType.ups,
        action = ActType.add,
        exec = execUpdate { UpstreamHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.ups,
        action = ActType.list,
        exec = {
          val upsNames = UpstreamHandle.names()
          CmdResult(upsNames, upsNames, utilJoinList(upsNames))
        }
      )
      it + ResAct(
        relation = ResourceType.ups,
        action = ActType.listdetail,
        exec = {
          val upsNames = UpstreamHandle.names()
          CmdResult(upsNames, upsNames, utilJoinList(upsNames))
        }
      )
      it + ResAct(
        relation = ResourceType.ups,
        action = ActType.remove,
        check = { UpstreamHandle.preRemoveCheck(it) },
        exec = execUpdate { UpstreamHandle.remove(it) }
      )
    }
    it + Res(ResourceType.sg) {
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.add,
        params = {
          it + ResActParam(Param.timeout, required)
          it + ResActParam(Param.period, required)
          it + ResActParam(Param.up, required)
          it + ResActParam(Param.down, required)
          it + ResActParam(Param.protocol)
          it + ResActParam(Param.meth) { MethHandle.get(it, "") }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
          it + ResActParam(Param.elg)
        },
        check = { HealthCheckHandle.getHealthCheckConfig(it) },
        exec = execUpdate { ServerGroupHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.ups),
        params = {
          it + ResActParam(Param.weight) { WeightHandle.check(it) }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        exec = execUpdate { ServerGroupHandle.attach(it) }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.list,
        exec = {
          val sgNames = ServerGroupHandle.names()
          CmdResult(sgNames, sgNames, utilJoinList(sgNames))
        }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.listdetail,
        exec = {
          val refs = ServerGroupHandle.details()
          val refStrList = refs.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(refs, refStrList, utilJoinList(refStrList))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.sg, ResRelation(ResourceType.ups)),
        action = ActType.list,
        exec = {
          val sgNames = ServerGroupHandle.names(it.resource.parentResource)
          CmdResult(sgNames, sgNames, utilJoinList(sgNames))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.sg, ResRelation(ResourceType.ups)),
        action = ActType.listdetail,
        exec = {
          val refs = ServerGroupHandle.details(it.resource.parentResource)
          val refStrList = refs.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(refs, refStrList, utilJoinList(refStrList))
        }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.update,
        params = {
          it + ResActParam(Param.timeout) { HealthCheckHandle.getHealthCheckConfig(it) }
          it + ResActParam(Param.period) { HealthCheckHandle.getHealthCheckConfig(it) }
          it + ResActParam(Param.up) { HealthCheckHandle.getHealthCheckConfig(it) }
          it + ResActParam(Param.down) { HealthCheckHandle.getHealthCheckConfig(it) }
          it + ResActParam(Param.protocol)
          it + ResActParam(Param.meth) { MethHandle.get(it, "") }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        exec = execUpdate { ServerGroupHandle.update(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.sg, ResRelation(ResourceType.ups)),
        action = ActType.update,
        params = {
          it + ResActParam(Param.weight) { WeightHandle.check(it) }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        exec = execUpdate { ServerGroupHandle.updateInUpstream(it) }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.remove,
        check = { ServerGroupHandle.preRemoveCheck(it) },
        exec = execUpdate { ServerGroupHandle.remove(it) }
      )
      it + ResAct(
        relation = ResourceType.sg,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.ups),
        exec = execUpdate { ServerGroupHandle.detach(it) }
      )
    }
    it + Res(ResourceType.el) {
      it + ResAct(
        relation = ResourceType.el,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.elg),
        params = {
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        exec = execUpdate { EventLoopHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.el, ResRelation(ResourceType.elg)),
        action = ActType.list,
        exec = {
          val elNames = EventLoopHandle.names(it.resource.parentResource)
          CmdResult(elNames, elNames, utilJoinList(elNames))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.el, ResRelation(ResourceType.elg)),
        action = ActType.listdetail,
        exec = {
          val els = EventLoopHandle.detail(it.resource.parentResource)
          val elStrList = els.stream().map { it.toString() }
            .collect(Collectors.toList())
          CmdResult(els, elStrList, utilJoinList(els))
        }
      )
      it + ResAct(
        relation = ResourceType.el,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.elg),
        exec = execUpdate { EventLoopHandle.remove(it) }
      )
    }
    it + Res(ResourceType.svr) {
      it + ResAct(
        relation = ResourceType.svr,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sg),
        params = {
          it + ResActParam(Param.addr, required) { AddrHandle.check(it) }
          it + ResActParam(Param.weight) { WeightHandle.check(it) }
        },
        exec = execUpdate { ServerHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.svr, ResRelation(ResourceType.sg)),
        action = ActType.list,
        exec = {
          val serverNames = ServerHandle.names(it.resource.parentResource)
          CmdResult(serverNames, serverNames, utilJoinList(serverNames))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.svr, ResRelation(ResourceType.sg)),
        action = ActType.listdetail,
        exec = {
          val svrRefList = ServerHandle.detail(it.resource.parentResource)
          val svrRefStrList = svrRefList.stream().map { it.toString() }
            .collect(Collectors.toList())
          CmdResult(svrRefList, svrRefStrList, utilJoinList(svrRefList))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.svr, ResRelation(ResourceType.sg)),
        action = ActType.update,
        params = {
          it + ResActParam(Param.weight) { WeightHandle.check(it) }
        },
        exec = execUpdate { ServerHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.svr,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.sg),
        exec = execUpdate { ServerHandle.remove(it) }
      )
    }
    it + Res(ResourceType.secg) {
      it + ResAct(
        relation = ResourceType.secg,
        action = ActType.add,
        params = {
          it + ResActParam(Param.secgrdefault, required) { SecGRDefaultHandle.check(it) }
        },
        exec = execUpdate { SecurityGroupHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.secg,
        action = ActType.list,
        exec = {
          val sgNames = SecurityGroupHandle.names()
          CmdResult(sgNames, sgNames, utilJoinList(sgNames))
        }
      )
      it + ResAct(
        relation = ResourceType.secg,
        action = ActType.listdetail,
        exec = {
          val secg = SecurityGroupHandle.detail()
          val secgStrList = secg.stream().map { it.toString() }
            .collect(Collectors.toList())
          CmdResult(secgStrList, secgStrList, utilJoinList(secg))
        }
      )
      it + ResAct(
        relation = ResourceType.secg,
        action = ActType.update,
        params = {
          it + ResActParam(Param.secgrdefault) { SecGRDefaultHandle.check(it) }
        },
        exec = execUpdate { SecurityGroupHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.secg,
        action = ActType.remove,
        check = { SecurityGroupHandle.preRemoveCheck(it) },
        exec = execUpdate { SecurityGroupHandle.remove(it) }
      )
    }
    it + Res(ResourceType.secgr) {
      it + ResAct(
        relation = ResourceType.secgr,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.secg),
        params = {
          it + ResActParam(Param.net, required) { NetworkHandle.check(it) }
          it + ResActParam(Param.protocol, required) { ProtocolHandle.check(it) }
          it + ResActParam(Param.portrange, required) { PortRangeHandle.check(it) }
          it + ResActParam(Param.secgrdefault, required) { SecGRDefaultHandle.check(it) }
        },
        exec = execUpdate { SecurityGroupRuleHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.secgr, ResRelation(ResourceType.secg)),
        action = ActType.list,
        exec = {
          val ruleNames = SecurityGroupRuleHandle.names(it.resource.parentResource)
          CmdResult(ruleNames, ruleNames, utilJoinList(ruleNames))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.secgr, ResRelation(ResourceType.secg)),
        action = ActType.listdetail,
        exec = {
          val rules = SecurityGroupRuleHandle.detail(it.resource.parentResource)
          val ruleStrList = rules.stream().map { it.toString() }
            .collect(Collectors.toList())
          CmdResult(rules, ruleStrList, utilJoinList(rules))
        }
      )
      it + ResAct(
        relation = ResourceType.secgr,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.secg),
        exec = execUpdate { SecurityGroupRuleHandle.remove(it) }
      )
    }
    it + Res(ResourceType.ck) {
      it + ResAct(
        relation = ResourceType.ck,
        action = ActType.add,
        params = {
          it + ResActParam(Param.cert, required)
          it + ResActParam(Param.key, required)
        },
        exec = execUpdate { CertKeyHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.ck,
        action = ActType.list,
        exec = {
          val names = CertKeyHandle.names()
          CmdResult(names, names, utilJoinList(names))
        }
      )
      it + ResAct(
        relation = ResourceType.ck,
        action = ActType.listdetail,
        exec = {
          val certs = CertKeyHandle.detail()
          CmdResult(certs, certs.map { it.toString() }, utilJoinList(certs))
        }
      )
      it + ResAct(
        relation = ResourceType.ck,
        action = ActType.remove,
        check = { CertKeyHandle.preRemoveCheck(it) },
        exec = execUpdate { CertKeyHandle.remove(it) }
      )
    }
    it + Res(ResourceType.dnscache) {
      it + ResAct(
        relation = ResourceType.dnscache,
        action = ActType.list,
        check = { ResolverHandle.checkResolver(it.resource.parentResource) },
        exec = {
          val cacheCnt = DnsCacheHandle.count()
          CmdResult(cacheCnt, cacheCnt, "" + cacheCnt)
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.dnscache, ResRelation(ResourceType.resolver)),
        action = ActType.listdetail,
        check = { ResolverHandle.checkResolver(it.resource.parentResource) },
        exec = {
          val caches = DnsCacheHandle.detail()
          val cacheStrList = caches.stream().map { c: io.vproxy.base.dns.Cache ->
            listOf(
              c.host,
              c.ipv4.stream().map { it.formatToIPString() }
                .collect(Collectors.toList()),
              c.ipv6.stream().map { it.formatToIPString() }
                .collect(Collectors.toList())
            )
          }.collect(Collectors.toList())
          CmdResult(caches, cacheStrList, utilJoinList(caches))
        }
      )
      it + ResAct(
        relation = ResourceType.dnscache,
        action = ActType.remove,
        check = { ResolverHandle.checkResolver(it.resource.parentResource) },
        exec = execUpdate { DnsCacheHandle.remove(it) }
      )
    }
    it + Res(ResourceType.sw) {
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.add,
        params = {
          it + ResActParam(Param.addr) { AddrHandle.check(it) }
          it + ResActParam(Param.mactabletimeout) { TimeoutHandle.check(it, Param.mactabletimeout) }
          it + ResActParam(Param.arptabletimeout) { TimeoutHandle.check(it, Param.arptabletimeout) }
          it + ResActParam(Param.elg)
          it + ResActParam(Param.secg)
          it + ResActParam(Param.mtu) { MTUHandle.check(it) }
          it + ResActParam(Param.flood) { FloodHandle.check(it) }
          it + ResActParam(Param.csumrecalc) { CsumRecalcHandle.check(it) }
        },
        exec = execUpdate { SwitchHandle.add(it) }
      )
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.list,
        exec = {
          val swNames = SwitchHandle.names()
          CmdResult(swNames, swNames, utilJoinList(swNames))
        }
      )
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.listdetail,
        exec = {
          val swRefList = SwitchHandle.details()
          val swRefStrList = swRefList.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(swRefList, swRefStrList, utilJoinList(swRefList))
        }
      )
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.update,
        params = {
          it + ResActParam(Param.mactabletimeout) { TimeoutHandle.check(it, Param.mactabletimeout) }
          it + ResActParam(Param.arptabletimeout) { TimeoutHandle.check(it, Param.arptabletimeout) }
          it + ResActParam(Param.secg)
          it + ResActParam(Param.mtu) { MTUHandle.check(it) }
          it + ResActParam(Param.flood) { FloodHandle.check(it) }
          it + ResActParam(Param.csumrecalc) { CsumRecalcHandle.check(it) }
          it + ResActParam(Param.trace) { TraceIntHandle.check(it) }
        },
        exec = execUpdate { SwitchHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.remove,
        exec = execUpdate { SwitchHandle.remove(it) }
      )
      it + ResAct(
        relation = ResourceType.sw,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.addr) { AddrHandle.check(it) }
        },
        flags = {
          it + ResActFlag(Flag.noswitchflag)
        },
        exec = execUpdate { SwitchHandle.attach(it) }
      )
    }
    it + Res(ResourceType.trace) {
      it + ResAct(
        relation = ResRelation(ResourceType.trace, ResRelation(ResourceType.sw)),
        action = ActType.list,
        exec = {
          val ls = TraceHandle.list(it.resource.parentResource)
          CmdResult(ls, ls.map { it.split("\n") }, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.trace, ResRelation(ResourceType.sw)),
        action = ActType.listdetail,
        exec = {
          val ls = TraceHandle.list(it.resource.parentResource)
          CmdResult(ls, ls.map { it.split("\n") }, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResourceType.trace,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.sw),
        check = { TraceHandle.checkTraceNum(it.resource) },
        exec = execUpdate { TraceHandle.remove(it) }
      )
    }
    it + Res(ResourceType.vrf) {
      it + ResAct(
        relation = ResourceType.vrf,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.v4net, required) {
            NetworkHandle.check(it, Param.v4net)
            val net = NetworkHandle.get(it, Param.v4net)
            if (net.ip.address.size != 4) {
              throw io.vproxy.base.util.exception.XException("invalid argument " + Param.v4net + ": not ipv4 network: " + net)
            }
          }
          it + ResActParam(Param.v6net) {
            NetworkHandle.check(it, Param.v6net)
            val net = NetworkHandle.get(it, Param.v6net)
            if (net.ip.address.size != 16) {
              throw io.vproxy.base.util.exception.XException("invalid argument " + Param.v6net + ": not ipv6 network: " + net)
            }
          }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        check = { VrfHandle.checkVrfName(it.resource) },
        exec = execUpdate { VrfHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        action = ActType.list,
        exec = {
          val vrfLs = VrfHandle.list(it.resource.parentResource)
          val ls = vrfLs.stream().map { it.vrf }.collect(Collectors.toList())
          CmdResult(vrfLs, ls, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        action = ActType.listdetail,
        exec = {
          val vrfLs = VrfHandle.list(it.resource.parentResource)
          val ls = vrfLs.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(vrfLs, ls, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResourceType.vrf,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.sw),
        check = { VrfHandle.checkVrfName(it.resource) },
        exec = execUpdate { VrfHandle.remove(it) }
      )
    }
    it + Res(ResourceType.iface) {
      it + ResAct(
        relation = ResRelation(ResourceType.iface, ResRelation(ResourceType.sw)),
        action = ActType.list,
        exec = {
          val cnt = IfaceHandle.count(it.resource.parentResource)
          CmdResult(cnt, cnt, "" + cnt)
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.iface, ResRelation(ResourceType.sw)),
        action = ActType.listdetail,
        exec = {
          val ifaces = IfaceHandle.list(it.resource.parentResource)
          val ls = ifaces.stream().map { it.name() + " -> " + it.toString() + " " + it.statistics.toString() }
            .collect(Collectors.toList())
          CmdResult(ifaces, ls, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.iface, ResRelation(ResourceType.sw)),
        action = ActType.update,
        params = {
          it + ResActParam(Param.mtu) { MTUHandle.check(it) }
          it + ResActParam(Param.flood) { FloodHandle.check(it) }
          it + ResActParam(Param.csumrecalc) { CsumRecalcHandle.check(it) }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
        },
        flags = {
          it + ResActFlag(Flag.enable)
          it + ResActFlag(Flag.disable)
        },
        check = {
          if (it.flags.contains(Flag.enable) && it.flags.contains(Flag.disable)) {
            throw io.vproxy.base.util.exception.XException("cannot specify enable and disable at the same time")
          }
        },
        exec = execUpdate { IfaceHandle.update(it) }
      )
      it + ResAct(
        relation = ResourceType.iface,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.sw),
        exec = {
          IfaceHandle.remove(it)
          CmdResult()
        }
      )
    }
    it + Res(ResourceType.arp) {
      it + ResAct(
        relation = ResourceType.arp,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        params = {
          it + ResActParam(Param.ip) { IpParamHandle.check(it) }
          it + ResActParam(Param.iface)
        },
        check = {
          ArpHandle.checkMacName(it.resource)
          if (!it.args.containsKey(Param.ip) && !(it.args.containsKey(Param.iface))) {
            throw io.vproxy.base.util.exception.XException("at lease one of ip|iface should be specified")
          }
          VrfHandle.checkVrfName(it.prepositionResource)
        },
        exec = {
          ArpHandle.add(it)
          CmdResult()
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.arp, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.list,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val cnt = ArpHandle.count(it.resource.parentResource)
          CmdResult(cnt, cnt, "" + cnt)
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.arp, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.listdetail,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val arpLs = ArpHandle.list(it.resource.parentResource)
          val ls = arpLs.stream().map { it.toString(arpLs) }.collect(Collectors.toList())
          CmdResult(arpLs, ls, utilJoinList(ls))
        }
      )
      it + ResAct(
        relation = ResourceType.arp,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        check = { ArpHandle.checkMacName(it.resource) },
        exec = {
          ArpHandle.remove(it)
          CmdResult()
        }
      )
    }
    it + Res(ResourceType.conntrack) {
      it + ResAct(
        relation = ResRelation(
          ResourceType.conntrack, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.list,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val cnt = ConntrackHandle.count(it.resource.parentResource)
          CmdResult(cnt, cnt, "" + cnt)
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.conntrack, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.listdetail,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val ctLs = ConntrackHandle.list(it.resource.parentResource)
          val tb = TableBuilder()
          ctLs.stream().forEach { it.buildTable(tb) }
          val str = tb.toString().trim()
          val array = ArrayList(if (str.isBlank()) listOf() else str.split("\n"))
          array.forEachIndexed { idx, s ->
            array[idx] = s.trim()
          }
          CmdResult(ctLs, array, str)
        }
      )
    }
    it + Res(ResourceType.tap) {
      it + ResAct(
        relation = ResourceType.tap,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
          it + ResActParam(Param.postscript)
        },
        check = {
          if (it.resource.alias.length > 15) {
            throw io.vproxy.base.util.exception.XException("tap dev name pattern too long: should <= 15")
          }
        },
        exec = execUpdate { TapHandle.add(it) }
      )
    }
    it + Res(ResourceType.tun) {
      it + ResAct(
        relation = ResourceType.tun,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
          it + ResActParam(Param.mac, required) { MacHandle.check(it) }
          it + ResActParam(Param.postscript)
        },
        check = {
          if (it.resource.alias.length > 15) {
            throw io.vproxy.base.util.exception.XException("tun dev name pattern too long: should <= 15")
          }
        },
        exec = execUpdate { TunHandle.add(it) }
      )
    }
    it + Res(ResourceType.fubuki) {
      it + ResAct(
        relation = ResourceType.fubuki,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.pass, required)
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
          it + ResActParam(Param.mac, required) { MacHandle.check(it) }
          it + ResActParam(Param.addr, required) { AddrHandle.check(it) }
          it + ResActParam(Param.ip) { IpParamHandle.check(it, true) }
        },
        exec = execUpdate { FubukiHandle.add(it) }
      )
    }
    it + Res(ResourceType.fubukietherip) {
      it + ResAct(
        relation = ResourceType.fubukietherip,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
          it + ResActParam(Param.ip) { IpParamHandle.check(it) }
        },
        exec = execUpdate { FubukiEtherIPHandle.add(it) }
      )
    }
    it + Res(ResourceType.xdp) {
      it + ResAct(
        relation = ResourceType.xdp,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.umem, required)
          it + ResActParam(Param.queue, required) { QueueHandle.check(it) }
          it + ResActParam(Param.rxringsize) { RingSizeHandle.check(it, Param.rxringsize) }
          it + ResActParam(Param.txringsize) { RingSizeHandle.check(it, Param.txringsize) }
          it + ResActParam(Param.mode) { BPFModeHandle.check(it) }
          it + ResActParam(Param.busypoll) { BusyPollHandle.check(it) }
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
        },
        flags = {
          it + ResActFlag(Flag.zerocopy)
          it + ResActFlag(Flag.rxgencsum)
          it + ResActFlag(Flag.offload)
        },
        exec = execUpdate { XDPHandle.add(it) }
      )
    }
    it + Res(ResourceType.vlan) {
      it + ResAct(
        relation = ResourceType.vlan,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.vrf, required) { VrfParamHandle.check(it) }
        },
        exec = execUpdate { VLanAdaptorHandle.add(it) }
      )
    }
    it + Res(ResourceType.ip) {
      it + ResAct(
        relation = ResourceType.ip,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        params = {
          it + ResActParam(Param.mac, required) { MacHandle.check(it) }
          it + ResActParam(Param.anno) { AnnotationsHandle.check(it) }
          it + ResActParam(Param.routing) { RoutingHandle.check(it) }
        },
        check = {
          IpHandle.checkIpName(it.resource)
          VrfHandle.checkVrfName(it.prepositionResource)
        },
        exec = execUpdate { IpHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.ip, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.list,
        check = {
          VrfHandle.checkVrfName(it.resource.parentResource)
        },
        exec = {
          val names = IpHandle.names(it.resource.parentResource)
          val strNames = names.stream().map { it.formatToIPString() }.collect(Collectors.toList())
          CmdResult(names, strNames, utilJoinList(strNames))
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.ip, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.listdetail,
        check = {
          VrfHandle.checkVrfName(it.resource.parentResource)
        },
        exec = {
          val tuples = IpHandle.list(it.resource.parentResource)
          val strTuples = tuples.stream().map {
            it.ip.formatToIPString() + " -> mac " + it.mac + " routing " + if (it.routing) {
              "on"
            } else {
              "off"
            } +
                if (it.annotations.isEmpty) "" else " annotations " + it.annotations
          }.collect(Collectors.toList())
          CmdResult(tuples, strTuples, utilJoinList(strTuples))
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.ip, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.update,
        params = {
          it + ResActParam(Param.routing) { RoutingHandle.check(it) }
        },
        check = {
          IpHandle.checkIpName(it.resource)
          VrfHandle.checkVrfName(it.resource.parentResource)
        },
        exec = {
          IpHandle.update(it)
          CmdResult()
        }
      )
      it + ResAct(
        relation = ResourceType.ip,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        check = {
          IpHandle.checkIpName(it.resource)
          VrfHandle.checkVrfName(it.prepositionResource)
        },
        exec = execUpdate { IpHandle.remove(it) }
      )
    }
    it + Res(ResourceType.route) {
      it + ResAct(
        relation = ResourceType.route,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        params = {
          it + ResActParam(Param.net, required) { NetworkHandle.check(it) }
          it + ResActParam(Param.vrf) { NetworkHandle.check(it) }
          it + ResActParam(Param.via) { NetworkHandle.check(it) }
        },
        check = {
          VrfHandle.checkVrfName(it.prepositionResource)
          RouteHandle.checkCreateRoute(it)
        },
        exec = execUpdate { RouteHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.route, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.list,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val names = RouteHandle.names(it.resource.parentResource)
          CmdResult(names, names, utilJoinList(names))
        }
      )
      it + ResAct(
        relation = ResRelation(
          ResourceType.route, ResRelation(
            ResourceType.vrf, ResRelation(
              ResourceType.sw
            )
          )
        ),
        action = ActType.listdetail,
        check = { VrfHandle.checkVrfName(it.resource.parentResource) },
        exec = {
          val routes = RouteHandle.list(it.resource.parentResource)
          val strTuples = routes.stream().map { it.toString() }.collect(Collectors.toList())
          CmdResult(routes, strTuples, utilJoinList(strTuples))
        }
      )
      it + ResAct(
        relation = ResourceType.route,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.vrf, ResRelation(ResourceType.sw)),
        check = { VrfHandle.checkVrfName(it.prepositionResource) },
        exec = execUpdate { RouteHandle.remove(it) }
      )
    }
    it + Res(ResourceType.umem) {
      it + ResAct(
        relation = ResourceType.umem,
        action = ActType.addto,
        targetRelation = ResRelation(ResourceType.sw),
        params = {
          it + ResActParam(Param.chunks) { RingSizeHandle.check(it, Param.chunks) }
          it + ResActParam(Param.fillringsize) { RingSizeHandle.check(it, Param.fillringsize) }
          it + ResActParam(Param.compringsize) { RingSizeHandle.check(it, Param.compringsize) }
          it + ResActParam(Param.framesize) { FrameSizeHandle.check(it) }
        },
        exec = execUpdate { UMemHandle.add(it) }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.umem, ResRelation(ResourceType.sw)),
        action = ActType.list,
        exec = {
          val names = UMemHandle.names(it.resource.parentResource)
          CmdResult(names, names, utilJoinList(names))
        }
      )
      it + ResAct(
        relation = ResRelation(ResourceType.umem, ResRelation(ResourceType.sw)),
        action = ActType.listdetail,
        exec = {
          val umems = UMemHandle.list(it.resource.parentResource)
          val strLs = umems.stream().map { u -> u.toString() }.collect(Collectors.toList())
          CmdResult(umems, strLs, utilJoinList(strLs))
        }
      )
      it + ResAct(
        relation = ResourceType.umem,
        action = ActType.removefrom,
        targetRelation = ResRelation(ResourceType.sw),
        // will check when executing: check = { UMemHandle.preRemoveCheck(it) },
        exec = execUpdate { UMemHandle.remove(it) }
      )
    }
  } // end init
}
