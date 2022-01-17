/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HttpContext extends LayerContext {

    private String cookie;

    private String lastRequestPath;

    public HttpContext(Context context) {
        super(context);
        context.setHttpContext(this);
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public String getLastRequestPath() {
        return lastRequestPath;
    }

    public void setLastRequestPath(String lastRequestPath) {
        this.lastRequestPath = lastRequestPath;
    }

}
