/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpHeader;
import de.rub.nds.tlsattacker.core.https.header.serializer.HttpsHeaderSerializer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class HttpsRequestSerializer extends ProtocolMessageSerializer<HttpsRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpsRequestMessage message;

    public HttpsRequestSerializer(HttpsRequestMessage message, ProtocolVersion version) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        StringBuilder builder = new StringBuilder();
        builder.append(message.getRequestType().getValue()).append(" ").append(message.getRequestPath().getValue())
                .append(" ").append(message.getRequestProtocol().getValue()).append("\r\n");
        for (HttpHeader header : message.getHeader()) {
            HttpsHeaderSerializer serializer = new HttpsHeaderSerializer(header);
            builder.append(new String(serializer.serialize(), StandardCharsets.ISO_8859_1));
        }
        builder.append("\r\n");
        LOGGER.info(builder.toString());
        appendBytes(builder.toString().getBytes(StandardCharsets.ISO_8859_1));
        return getAlreadySerialized();
    }

    @Override
    protected byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }

}
