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
import de.rub.nds.tlsattacker.core.http.header.serializer.HttpHeaderSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpResponseSerializer extends HttpMessageSerializer<HttpResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpResponseMessage message;

    public HttpResponseSerializer(HttpResponseMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder builder = new StringBuilder();
        builder.append(message.getResponseProtocol().getValue())
                .append(" ")
                .append(message.getResponseStatusCode().getValue())
                .append("\r\n");
        for (HttpHeader header : message.getHeader()) {
            HttpHeaderSerializer serializer = new HttpHeaderSerializer(header);
            builder.append(new String(serializer.serialize()));
        }
        builder.append("\r\n");
        builder.append(message.getResponseContent().getValue());
        LOGGER.info(builder.toString());
        appendBytes(builder.toString().getBytes(StandardCharsets.ISO_8859_1));
        return getAlreadySerialized();
    }
}
