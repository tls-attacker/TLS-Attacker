/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class HttpsResponseSerializerTest {

    private Config config;

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of("HTTP/1.1 200 OK\r\nHost: rub.com\r\nContent-Type: text/html\r\n\r\ndata\r\n"
            .getBytes(StandardCharsets.US_ASCII), ProtocolVersion.TLS12));
    }

    /**
     * Test of serializeProtocolMessageContent method, of class HttpsResponseSerializer.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerializeProtocolMessageContent(byte[] providedMessageBytes,
        ProtocolVersion providedProtocolVersion) {
        HttpsResponseParser parser = new HttpsResponseParser(0, providedMessageBytes, providedProtocolVersion, config);
        HttpsResponseMessage parsedMsg = parser.parse();
        HttpsResponseSerializer serializer = new HttpsResponseSerializer(parsedMsg, providedProtocolVersion);

        assertArrayEquals(providedMessageBytes, serializer.serialize());
    }

}