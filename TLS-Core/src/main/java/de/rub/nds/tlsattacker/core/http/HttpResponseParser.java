/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.http;

import java.io.InputStream;
import java.nio.charset.Charset;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.http.header.*;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpResponseParser extends HttpMessageParser<HttpResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HttpResponseParser(InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageContent(HttpResponseMessage message) {
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
                throw new ParserException("Could not parse " + split + " as HttpHeader");
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
                    header = new GenericHttpHeader();
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
