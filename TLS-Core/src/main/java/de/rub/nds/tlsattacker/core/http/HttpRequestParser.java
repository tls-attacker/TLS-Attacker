/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.http.header.ContentLengthHeader;
import de.rub.nds.tlsattacker.core.http.header.DateHeader;
import de.rub.nds.tlsattacker.core.http.header.ExpiresHeader;
import de.rub.nds.tlsattacker.core.http.header.GenericHttpHeader;
import de.rub.nds.tlsattacker.core.http.header.HostHeader;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsattacker.core.http.header.LocationHeader;
import de.rub.nds.tlsattacker.core.http.header.TokenBindingHeader;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpRequestParser extends HttpMessageParser<HttpRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HttpRequestParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(HttpRequestMessage message) {
        String request = parseStringTill((byte) 0x0A).trim();
        String[] split = request.replaceAll("\r", " ").split(" ");
        if (split.length != 3) {
            throw new ParserException("Could not parse as HttpRequestMessage");
        }
        message.setRequestType(split[0]);
        message.setRequestPath(split[1]);
        message.setRequestProtocol(split[2]);
        String line = parseStringTill((byte) 0x0A);

        // compatible with \r\n and \n line endings
        while (!line.trim().isEmpty()) {
            split = line.split(": ");
            if (split.length < 2) {
                throw new ParserException("Could not parse " + split + " as HttpHeader");
            }
            HttpHeader header;
            String headerName = split[0];
            String headerValue =
                    line.replaceFirst(split[0] + ":", "")
                            .replaceAll("\n", "")
                            .replaceAll("\r", "")
                            .trim();
            switch (headerName.toLowerCase()) {
                case "host":
                    header = new HostHeader();
                    break;
                case "sec-token-binding":
                    header = new TokenBindingHeader();
                    break;
                case "location":
                    header = new LocationHeader();
                    break;
                case "content-length":
                    header = new ContentLengthHeader();
                    break;
                case "expires":
                    header = new ExpiresHeader();
                    break;
                case "date":
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
        LOGGER.info(new String(getAlreadyParsed(), StandardCharsets.US_ASCII));
    }
}
