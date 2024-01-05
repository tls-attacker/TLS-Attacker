/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.tlsattacker.core.http.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.layer.context.HttpContext;
import java.nio.charset.StandardCharsets;

public class HttpResponsePreparator extends HttpMessagePreparator<HttpResponseMessage> {

    private final HttpResponseMessage message;

    private final HttpContext httpContext;

    public HttpResponsePreparator(HttpContext httpContext, HttpResponseMessage message) {
        super(httpContext.getChooser(), message);
        this.httpContext = httpContext;
        this.message = message;
    }

    @Override
    protected void prepareHttpMessageContents() {
        message.setResponseProtocol("HTTP/1.1");
        message.setResponseStatusCode("200 OK");
        message.setResponseContent(chooser.getConfig().getDefaultApplicationMessageData());

        for (HttpHeader header : message.getHeader()) {
            if (header instanceof ContentLengthHeader) {
                ((ContentLengthHeader) header)
                        .setConfigLength(
                                message.getResponseContent()
                                        .getValue()
                                        .getBytes(StandardCharsets.ISO_8859_1)
                                        .length);
            }
            header.getPreparator(httpContext).prepare();
        }
    }
}
