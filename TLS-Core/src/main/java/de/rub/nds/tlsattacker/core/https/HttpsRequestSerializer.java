/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.serializer.HttpsHeaderSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsRequestSerializer extends ProtocolMessageSerializer<HttpsRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HttpsRequestMessage message;

    public HttpsRequestSerializer(HttpsRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        StringBuilder builder = new StringBuilder();
        builder.append(message.getRequestType().getValue()).append(" ").append(message.getRequestPath().getValue())
                .append(" ").append(message.getRequestProtocol().getValue()).append("\r\n");
        for (HttpsHeader header : message.getHeader()) {
            HttpsHeaderSerializer serializer = new HttpsHeaderSerializer(header);
            builder.append(new String(serializer.serialize()));
        }
        builder.append("\r\n");
        LOGGER.info(builder.toString());
        appendBytes(builder.toString().getBytes());
        return getAlreadySerialized();
    }

}
