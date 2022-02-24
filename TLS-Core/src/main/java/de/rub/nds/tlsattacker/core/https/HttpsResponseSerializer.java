/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpHeader;
import de.rub.nds.tlsattacker.core.https.header.serializer.HttpsHeaderSerializer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsResponseSerializer extends ProtocolMessageSerializer<HttpsResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpsResponseMessage message;

    public HttpsResponseSerializer(HttpsResponseMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        StringBuilder builder = new StringBuilder();
        builder.append(message.getResponseProtocol().getValue()).append(" ")
            .append(message.getResponseStatusCode().getValue()).append("\r\n");
        for (HttpHeader header : message.getHeader()) {
            HttpsHeaderSerializer serializer = new HttpsHeaderSerializer(header);
            builder.append(new String(serializer.serialize()));
        }
        builder.append("\r\n");
        builder.append(message.getResponseContent().getValue());
        LOGGER.info(builder.toString());
        appendBytes(builder.toString().getBytes(StandardCharsets.ISO_8859_1));
        return getAlreadySerialized();
    }

    @Override
    protected byte[] serializeBytes() {
        return serializeProtocolMessageContent();
    }
}
