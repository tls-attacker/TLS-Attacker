/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https.header.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

public class HttpsHeaderParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of("Host: rub.com\r\n".getBytes(StandardCharsets.US_ASCII), 0, "Host", "rub.com"));
    }

    /**
     * Test of testParse method, of class HttpsHeaderParser.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedHeaderBytes, int providedStart, String expectedHeaderName,
        String expectedHeaderValue) {
        HttpsHeaderParser parser = new HttpsHeaderParser(providedStart, providedHeaderBytes);
        HttpsHeader header = parser.parse();

        assertEquals(expectedHeaderName, header.getHeaderName().getValue());
        assertEquals(expectedHeaderValue, header.getHeaderValue().getValue());
    }

}