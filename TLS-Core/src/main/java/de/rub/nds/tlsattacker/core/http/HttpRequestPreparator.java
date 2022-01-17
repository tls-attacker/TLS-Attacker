/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import de.rub.nds.tlsattacker.core.protocol.Preparator;

public class HttpRequestPreparator extends Preparator<HttpRequestMessage> {

    private final HttpRequestMessage message;

    private final HttpContext httpContext;

    public HttpRequestPreparator(HttpContext httpContext, HttpRequestMessage message) {
        super(httpContext.getChooser(), message);
        this.httpContext = httpContext;
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setRequestPath("/");
        message.setRequestProtocol("HTTP/1.1");
        message.setRequestType("GET");
        for (HttpHeader header : message.getHeader()) {
            header.getPreparator(httpContext).prepare();
        }
    }

}
