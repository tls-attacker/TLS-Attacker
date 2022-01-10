package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HttpContext extends LayerContext {

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
