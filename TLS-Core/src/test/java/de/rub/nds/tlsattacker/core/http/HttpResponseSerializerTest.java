/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class HttpResponseSerializerTest {

    private Config config;

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        "HTTP/1.1 200 OK\r\nHost: rub.com\r\nContent-Type: text/html\r\n\r\ndata\r\n"
                                .getBytes(StandardCharsets.US_ASCII),
                        ProtocolVersion.TLS12));
    }

    /** Test of serializeProtocolMessageContent method, of class HttpsResponseSerializer. */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerializeProtocolMessageContent(
            byte[] providedMessageBytes, ProtocolVersion providedProtocolVersion) {
        HttpResponseParser parser =
                new HttpResponseParser(new ByteArrayInputStream(providedMessageBytes));
        HttpResponseMessage parsedMsg = new HttpResponseMessage();
        parser.parse(parsedMsg);
        HttpResponseSerializer serializer = new HttpResponseSerializer(parsedMsg);

        assertArrayEquals(providedMessageBytes, serializer.serialize());
    }
}
