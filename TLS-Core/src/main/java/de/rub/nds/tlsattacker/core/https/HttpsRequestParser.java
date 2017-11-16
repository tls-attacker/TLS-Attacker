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

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class HttpsRequestParser extends ProtocolMessageParser<HttpsRequestMessage> {

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
        byte[] bytesLeft = parseArrayOrTillEnd(getBytesLeft());
        int pointer = 0;
        while (getBytesLeft() > 0) {
            HttpsHeaderParser parser = new HttpsHeaderParser(pointer, bytesLeft);
            HttpsHeader header = parser.parse();
            message.getHeader().add(header);
            if (pointer == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing HttpsHeader");
            }
            pointer = parser.getPointer();

        }
        LOGGER.info(new String(getAlreadyParsed(), Charset.forName("ASCII")));
        return message;
    }

}
