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
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.parser.HttpsHeaderParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import java.nio.charset.Charset;

public class HttpsResponseParser extends ProtocolMessageParser<HttpsResponseMessage> {

    public HttpsResponseParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, version);
    }

    @Override
    protected HttpsResponseMessage parseMessageContent() {
        HttpsResponseMessage message = new HttpsResponseMessage();
        String request = parseStringTill((byte) 0x0A);
        String[] split = request.replaceAll("\r", " ").split(" ");
        if (split.length < 2) {
            throw new ParserException("Could not parse as HttpsResponseMessage");
        }
        message.setResponseProtocol(split[0]);
        message.setResponseStatusCode(request.replaceFirst(split[0] + " ", ""));
        String line = parseStringTill((byte) 0x0A);
        while (!line.equals("\r\n")) {
            HttpsHeaderParser parser = new HttpsHeaderParser(0, line.getBytes(Charset.forName("ASCII")));
            HttpsHeader header = parser.parse();
            message.getHeader().add(header);
            line = parseStringTill((byte) 0x0A);
        }
        byte[] content = parseArrayOrTillEnd(getBytesLeft());
        message.setResponseContent(new String(content, Charset.forName("ASCII")));
        LOGGER.info(new String(getAlreadyParsed()));
        return message;
    }
}
