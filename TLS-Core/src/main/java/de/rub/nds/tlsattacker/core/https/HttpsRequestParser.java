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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsRequestParser extends ProtocolMessageParser<HttpsRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HttpsRequestParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, version);
    }

    @Override
    protected HttpsRequestMessage parseMessageContent() {
        HttpsRequestMessage message = new HttpsRequestMessage();
        String request = parseStringTill((byte) 0x0A).trim();
        String[] split = request.replaceAll("\r", " ").split(" ");
        if (split.length != 3) {
            throw new ParserException("Could not parse as HttpsRequestMessage");
        }
        message.setRequestType(split[0]);
        message.setRequestPath(split[1]);
        message.setRequestProtocol(split[2]);
        String line = parseStringTill((byte) 0x0A);

        // compatible with \r\n and \n line endings
        while (!line.trim().isEmpty()) {
            HttpsHeaderParser parser = new HttpsHeaderParser(0, line.getBytes(Charset.forName("ASCII")));
            HttpsHeader header = parser.parse();
            message.getHeader().add(header);
            line = parseStringTill((byte) 0x0A);
        }
        LOGGER.info(new String(getAlreadyParsed(), Charset.forName("ASCII")));
        return message;
    }

}
