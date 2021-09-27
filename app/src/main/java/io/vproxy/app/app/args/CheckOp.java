package io.vproxy.app.app.args;

import io.vproxy.app.app.MainCtx;
import io.vproxy.app.app.MainOp;

public class CheckOp implements MainOp {
    @Override
    public String key() {
        return "check";
    }

    @Override
    public int argCount() {
        return 0;
    }

    @Override
    public int order() {
        return 0;
    }

    @Override
    public int pre(MainCtx ctx, String[] args) {
        return 0;
    }

    @Override
    public int execute(MainCtx ctx, String[] args) {
        ctx.set("isCheck", true);
        return 0;
    }
}
