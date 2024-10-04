package io.vproxy.app.app.cmd.handle.resource;

import io.vproxy.app.app.Application;
import io.vproxy.app.app.cmd.Command;
import io.vproxy.app.app.cmd.Param;
import io.vproxy.app.app.cmd.Resource;
import io.vproxy.app.app.cmd.handle.param.AnnotationsHandle;
import io.vproxy.app.app.cmd.handle.param.NetworkHandle;
import io.vproxy.base.util.Annotations;
import io.vproxy.base.util.Network;
import io.vproxy.vswitch.Switch;
import io.vproxy.vswitch.VirtualNetwork;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class VrfHandle {
    private VrfHandle() {
    }

    public static void checkVrfName(Resource resource) throws Exception {
        String vrf = resource.alias;
        try {
            Integer.parseInt(vrf);
        } catch (NumberFormatException e) {
            throw new Exception("vrf name should be an integer");
        }
    }

    public static VirtualNetwork get(Resource self) throws Exception {
        int vrf = Integer.parseInt(self.alias);
        Switch sw = SwitchHandle.get(self.parentResource);
        return sw.getNetwork(vrf);
    }

    public static void add(Command cmd) throws Exception {
        Switch sw = SwitchHandle.get(cmd.prepositionResource);
        Network v4net = NetworkHandle.get(cmd.args.get(Param.v4net));
        Network v6net = null;
        if (cmd.args.containsKey(Param.v6net)) {
            v6net = NetworkHandle.get(cmd.args.get(Param.v6net));
        }
        Annotations annotations = null;
        if (cmd.args.containsKey(Param.anno)) {
            annotations = AnnotationsHandle.get(cmd);
        }
        sw.addNetwork(Integer.parseInt(cmd.resource.alias), v4net, v6net, annotations);
    }

    public static void remove(Command cmd) throws Exception {
        Switch sw = SwitchHandle.get(cmd.prepositionResource);
        sw.delNetwork(Integer.parseInt(cmd.resource.alias));
    }

    public static List<VrfEntry> list(Resource parentResource) throws Exception {
        Switch sw = Application.get().switchHolder.get(parentResource.alias);
        var networks = sw.getNetworks().values();

        List<VrfEntry> ls = new ArrayList<>();
        for (var net : networks) {
            ls.add(new VrfEntry(net.vrf, net.v4network, net.v6network, net.getAnnotations()));
        }
        ls.sort(Comparator.comparingInt(a -> a.vrf));
        return ls;
    }

    public static class VrfEntry {
        public final int vrf;
        public final Network v4network;
        public final Network v6network;
        public final Annotations annotations;

        public VrfEntry(int vrf, Network v4network, Network v6network, Annotations annotations) {
            this.vrf = vrf;
            this.v4network = v4network;
            this.v6network = v6network;
            this.annotations = annotations;
        }

        @Override
        public String toString() {
            return vrf + " -> v4network " + v4network
                   + (v6network != null ? (" v6network " + v6network) : "")
                   + (!annotations.isEmpty() ? (" annotations " + annotations) : "");
        }
    }
}
