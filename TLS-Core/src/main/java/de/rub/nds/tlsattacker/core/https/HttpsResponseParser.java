/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.parser.HttpsHeaderParser;

import java.nio.charset.Charset;

import de.rub.nds.tlsattacker.core.protocol.parser.TlsMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsResponseParser extends TlsMessageParser<HttpsResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HttpsResponseParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, version, config);
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
        message.setResponseStatusCode(request.replaceFirst(split[0] + " ", "").trim());
        String line = parseStringTill((byte) 0x0A);

        // compatible with \r\n and \n line endings
        while (!line.trim().isEmpty()) {
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
