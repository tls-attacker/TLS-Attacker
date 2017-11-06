/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state.http;

public class HttpContext {

    private String cookie;

    private String lastRequestPath;

    public HttpContext() {
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
