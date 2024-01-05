/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;

public class HttpRequestPreparator extends HttpMessagePreparator<HttpRequestMessage> {

    private final HttpRequestMessage message;

    private final HttpContext httpContext;

    public HttpRequestPreparator(HttpContext httpContext, HttpRequestMessage message) {
        super(httpContext.getChooser(), message);
        this.httpContext = httpContext;
        this.message = message;
    }

    @Override
    public void prepareHttpMessageContents() {
        message.setRequestPath(httpContext.getChooser().getConfig().getDefaultHttpsRequestPath());
        message.setRequestProtocol("HTTP/1.1");
        message.setRequestType("GET");
        for (HttpHeader header : message.getHeader()) {
            header.getPreparator(httpContext).prepare();
        }
    }
}
