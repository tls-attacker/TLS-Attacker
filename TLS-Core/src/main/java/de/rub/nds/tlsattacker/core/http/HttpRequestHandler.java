/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.layer.context.HttpContext;

public class HttpRequestHandler extends HttpMessageHandler<HttpRequestMessage> {

    private final HttpContext httpContext;

    public HttpRequestHandler(HttpContext httpContext) {
        this.httpContext = httpContext;
    }

    @Override
    public void adjustContext(HttpRequestMessage message) {
        httpContext.setLastRequestPath(message.getRequestPath().getValue());
    }
}
