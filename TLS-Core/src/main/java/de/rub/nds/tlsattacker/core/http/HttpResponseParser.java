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
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HttpResponseParser extends HttpMessageParser<HttpResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final byte LINEBREAK_BYTE = (byte) 0x0A;

    private final int maxHttpLength;
    private ContentLengthHeader contentLengthHeader;
    private GenericHttpHeader transferEncodingHeader;

    public HttpResponseParser(InputStream stream, int maxHttpLength) {
        super(stream);
        this.maxHttpLength = maxHttpLength;
    }

    /**
     * Parses an HTTP response message from wire.
     *
     * @param message object that should be filled with content.
     */
    @Override
    public void parse(HttpResponseMessage message) {
        String request = parseStringTill(LINEBREAK_BYTE);
        String[] split = request.replace("\r", " ").split(" ");
        if (split.length < 2) {
            throw new ParserException("Could not parse as HttpsResponseMessage");
        }
        message.setResponseProtocol(split[0]);
        message.setResponseStatusCode(request.replaceFirst(split[0] + " ", "").trim());

        message.setHeader(parseHeaders());

        if (contentLengthHeader != null && transferEncodingHeader != null) {
            LOGGER.warn(
                    "HTTP message contains both Content-Length and Transfer-Encoding headers, assuming Content-Length");
        }

        StringBuilder httpMessageBuilder = new StringBuilder();
        if (contentLengthHeader != null) {
            parseContentLength(contentLengthHeader, httpMessageBuilder);
        } else if (transferEncodingHeader != null) {
            parseChunked(httpMessageBuilder, message);
        } else {
            // without headers defining parsing behavior or length we parse until the end of the
            // stream
            httpMessageBuilder.append(new String(parseTillEnd(), StandardCharsets.UTF_8));
        }
        message.setResponseContent(httpMessageBuilder.toString());
        LOGGER.debug(() -> new String(getAlreadyParsed(), StandardCharsets.UTF_8));
    }

    /** Parses all HTTP headers from the message: known and unknown. */
    private List<HttpHeader> parseHeaders() {

        String line = parseStringTill(LINEBREAK_BYTE);
        String[] split;
        List<HttpHeader> headers = new LinkedList<>();

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

            headers.add(header);
            line = parseStringTill(LINEBREAK_BYTE);
        }
        return headers;
    }

    /**
     * Parses the body of the HTTP message according to the given Content-Length header.
     *
     * @param contentLengthHeader The Content-Length header of the HTTP message.
     * @param httpMessageBuilder MessageBuilder to append parsed bytes to.
     */
    private void parseContentLength(
            ContentLengthHeader contentLengthHeader, StringBuilder httpMessageBuilder) {
        LOGGER.debug("Parsing HTTP message with Content Length Header");
        // get bytes to parse from header
        int bytesToRead;
        try {
            bytesToRead = Integer.parseInt(contentLengthHeader.getHeaderValue().getValue());
        } catch (NumberFormatException e) {
            LOGGER.warn(
                    "Server send invalid content length header, header value {} cannot be parsed to int",
                    contentLengthHeader.getHeaderValue().getValue());
            bytesToRead = getBytesLeft();
        }

        if (bytesToRead > maxHttpLength) {
            LOGGER.warn(
                    "Received a HTTP message with size {}, truncating to maximum specified size {}",
                    bytesToRead,
                    maxHttpLength);
            bytesToRead = maxHttpLength;
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
    }

    /**
     * Parses the body of the HTTP message using chunked encoding.
     *
     * @param httpMessageBuilder MessageBuilder to append parsed bytes to.
     */
    private void parseChunked(StringBuilder httpMessageBuilder, HttpResponseMessage message) {
        LOGGER.debug("Parsing HTTP message with chunked encoding.");
        // the body is encoded using <content length>\r\n<content>\r\n repeatedly, finished with
        // 0\r\n\r\n
        boolean reachedEnd = false;
        int parsedLen = 0;
        while (!reachedEnd && parsedLen < maxHttpLength) {
            // parse length line
            int length;
            try {
                length = Integer.parseInt(parseStringTill(LINEBREAK_BYTE).trim(), 16);
            } catch (NumberFormatException e) {
                LOGGER.warn("Invalid Chunked Encoding in HTTP message: ", e);
                return;
            }
            if (length == 0) {
                // parse all optional trailers
                reachedEnd = true;
                message.setTrailer(parseHeaders());
            } else {
                // read data of single chunk
                if (length >= maxHttpLength - parsedLen) {
                    length = maxHttpLength - parsedLen;
                    LOGGER.warn(
                            "Received a chunked HTTP message that is larger than the maximum specified size {}, truncating.",
                            maxHttpLength);
                }
                parsedLen += length;
                byte[] content = parseByteArrayField(length);
                httpMessageBuilder.append(new String(content, StandardCharsets.UTF_8));
                parseByteArrayField(2);
            }
        }
    }
}
