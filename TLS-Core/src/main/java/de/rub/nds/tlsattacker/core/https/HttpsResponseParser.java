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
import de.rub.nds.tlsattacker.core.https.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.https.header.DateHeader;
import de.rub.nds.tlsattacker.core.https.header.ExpiresHeader;
import de.rub.nds.tlsattacker.core.https.header.GenericHttpsHeader;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpHeader;
import de.rub.nds.tlsattacker.core.https.header.LocationHeader;
import de.rub.nds.tlsattacker.core.https.header.TokenBindingHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import java.io.InputStream;
import java.nio.charset.Charset;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpsResponseParser extends ProtocolMessageParser<HttpsResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HttpsResponseParser(InputStream stream, ProtocolVersion version, Config config) {
        super(stream, config);
    }

    @Override
    protected void parseMessageContent(HttpsResponseMessage message) {
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
            split = line.split(": ");
            if (split.length < 2) {
                throw new ParserException("Could not parse " + split + " as HttpsHeader");
            }
            HttpHeader header;
            String headerName = split[0];
            String headerValue = line.replaceFirst(split[0] + ":", "").replaceAll("\n", "").replaceAll("\r", "").trim();
            switch (headerName) {
                case "Host":
                    header = new HostHeader();
                    break;
                case "Sec-Token-Binding":
                    header = new TokenBindingHeader();
                    break;
                case "Location":
                    header = new LocationHeader();
                    break;
                case "Content-Length":
                    header = new ContentLengthHeader();
                    break;
                case "Expires":
                    header = new ExpiresHeader();
                    break;
                case "Date":
                    header = new DateHeader();
                    break;
                default:
                    header = new GenericHttpsHeader();
            }
            header.setHeaderName(headerName);
            header.setHeaderValue(headerValue);

            message.getHeader().add(header);
            line = parseStringTill((byte) 0x0A);
        }
        byte[] content = parseArrayOrTillEnd(getBytesLeft());
        message.setResponseContent(new String(content, Charset.forName("ASCII")));
        LOGGER.info(new String(getAlreadyParsed()));
    }
}
