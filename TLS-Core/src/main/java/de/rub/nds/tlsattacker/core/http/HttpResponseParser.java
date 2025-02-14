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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpResponseParser extends HttpMessageParser<HttpResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final byte LINEBREAK_BYTE = (byte) 0x0A;

    private int maxHttpLength;

    public HttpResponseParser(InputStream stream) {
        super(stream);
    }

    public HttpResponseParser(InputStream stream, int maxHttpLength) {
        super(stream);
        this.maxHttpLength = maxHttpLength;
    }

    @Override
    public void parse(HttpResponseMessage message) {
        // needed for body parsing in the end, set during header parsing
        ContentLengthHeader contentLengthHeader = null;
        GenericHttpHeader transferEncodingHeader = null;

        String request = parseStringTill(LINEBREAK_BYTE);
        String[] split = request.replace("\r", " ").split(" ");
        if (split.length < 2) {
            throw new ParserException("Could not parse as HttpsResponseMessage");
        }
        message.setResponseProtocol(split[0]);
        message.setResponseStatusCode(request.replaceFirst(split[0] + " ", "").trim());
        String line = parseStringTill(LINEBREAK_BYTE);

        // compatible with \r\n and \n line endings
        while (!line.trim().isEmpty()) {
            split = line.split(": ");
            if (split.length < 2) {
                throw new ParserException(
                        "Could not parse " + Arrays.toString(split) + " as HttpHeader");
            }
            HttpHeader header;
            String headerName = split[0];
            String headerValue =
                    line.replaceFirst(split[0] + ":", "")
                            .replace("\n", "")
                            .replace("\r", "")
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
                    contentLengthHeader = (ContentLengthHeader) header;
                    break;
                case "expires":
                    header = new ExpiresHeader();
                    break;
                case "date":
                    header = new DateHeader();
                    break;
                case "transfer-encoding":
                    header = new GenericHttpHeader();
                    transferEncodingHeader = (GenericHttpHeader) header;
                    break;
                default:
                    header = new GenericHttpHeader();
            }
            header.setHeaderName(headerName);
            header.setHeaderValue(headerValue);

            message.getHeader().add(header);
            line = parseStringTill(LINEBREAK_BYTE);
        }

        // parse content as content-length or chunked when either header is present, parse until end
        // of stream when
        // none is present

        StringBuilder httpMessageBuilder = new StringBuilder();

        if (contentLengthHeader != null && transferEncodingHeader != null) {
            LOGGER.warn(
                    "HTTP message contains both Content-Length and Transfer-Encoding headers, assuming Content-Length");
        }

        if (contentLengthHeader != null) {
            LOGGER.debug("Parsing HTTP message with Content Length Header");
            // get bytes to parse from header
            int bytesToRead;
            try {
                bytesToRead =
                        Math.min(
                                maxHttpLength,
                                Integer.parseInt(contentLengthHeader.getHeaderValue().getValue()));
            } catch (NumberFormatException e) {
                LOGGER.warn(
                        "Server send invalid content length header, header value {} cannot be parsed to int",
                        contentLengthHeader.getHeaderValue().getValue());
                bytesToRead = getBytesLeft();
            }
            // persist them
            byte[] content = parseByteArrayField(bytesToRead);
            httpMessageBuilder.append(new String(content, StandardCharsets.UTF_8));
            if (content.length < bytesToRead) {
                LOGGER.warn(
                        "Content-Length header value was larger ({}B) than actual content ({}B)",
                        bytesToRead,
                        content.length);
            }

        } else if (transferEncodingHeader != null) {
            LOGGER.debug("Parsing HTTP message with chunked encoding.");
            // the body is encoded using <content length>\r\n<content>\r\n repeatedly, finished with
            // 0\r\n\r\n
            boolean reachedEnd = false;
            int parsed_len = 0;
            while (!reachedEnd && parsed_len < maxHttpLength) {
                // parse length line
                int length;
                try {
                    length = Integer.parseInt(parseStringTill(LINEBREAK_BYTE).trim(), 16);
                } catch (NumberFormatException e) {
                    LOGGER.warn("Invalid Chunked Encoding in HTTP message: ", e);
                    return;
                }
                if (length == 0) {
                    // parse all trailing fields and last line
                    reachedEnd = true;
                    boolean parsedAllTrailing = false;
                    while (!parsedAllTrailing) {
                        String trailerLine = parseStringTill(LINEBREAK_BYTE);
                        if (trailerLine.length() > 2) {
                            // trailer line
                            httpMessageBuilder.append(trailerLine);
                        } else {
                            // last line
                            parsedAllTrailing = true;
                        }
                    }
                } else {
                    int actual_length = Math.min(maxHttpLength - parsed_len, length);
                    parsed_len += actual_length;
                    byte[] content;
                    if (actual_length < length) {
                        content = parseByteArrayField(length);
                    } else {
                        // parse length many bytes and then expect \r\n
                        content = parseByteArrayField(length + 2);
                    }
                    httpMessageBuilder.append(new String(content, StandardCharsets.UTF_8));
                }
            }
        } else {
            // without headers defining parsing behavior or length we parse until the end of the
            // stream
            httpMessageBuilder.append(new String(parseTillEnd(), StandardCharsets.UTF_8));
        }

        message.setResponseContent(httpMessageBuilder.toString());
        LOGGER.debug(() -> new String(getAlreadyParsed(), StandardCharsets.UTF_8));
    }
}
