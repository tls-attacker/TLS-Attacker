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

public class HttpRequestSerializer extends HttpMessageSerializer<HttpRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpRequestMessage message;

    public HttpRequestSerializer(HttpRequestMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder builder = new StringBuilder();
        builder.append(message.getRequestType().getValue())
                .append(" ")
                .append(message.getRequestPath().getValue())
                .append(" ")
                .append(message.getRequestProtocol().getValue())
                .append("\r\n");
        for (HttpHeader header : message.getHeader()) {
            HttpHeaderSerializer serializer = new HttpHeaderSerializer(header);
            builder.append(new String(serializer.serialize(), StandardCharsets.ISO_8859_1));
        }
        builder.append("\r\n");
        LOGGER.debug(builder.toString());
        appendBytes(builder.toString().getBytes(StandardCharsets.ISO_8859_1));
        return getAlreadySerialized();
    }
}
