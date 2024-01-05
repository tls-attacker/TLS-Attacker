/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class PSKBinderParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "2034c8ead79d29168694fcbff00106f86005ddf0a6480ea86cf06d8440752b62f9"),
                        32,
                        ArrayConverter.hexStringToByteArray(
                                "34c8ead79d29168694fcbff00106f86005ddf0a6480ea86cf06d8440752b62f9")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedPskBinderBytes,
            int expectedBinderEntryLength,
            byte[] expectedBinderEntry) {
        PSKBinderParser parser =
                new PSKBinderParser(new ByteArrayInputStream(providedPskBinderBytes));
        PSKBinder pskBinder = new PSKBinder();
        parser.parse(pskBinder);

        assertEquals(expectedBinderEntryLength, (long) pskBinder.getBinderEntryLength().getValue());
        assertArrayEquals(expectedBinderEntry, pskBinder.getBinderEntry().getValue());
    }
}
