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
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeySharePairParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        32,
                        ArrayConverter.hexStringToByteArray(
                                "2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        ArrayConverter.hexStringToByteArray("001D")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedKeySharePairBytes,
            int expectedKeyShareLength,
            byte[] expectedKeyShare,
            byte[] expectedKeyShareType) {
        KeyShareEntryParser parser =
                new KeyShareEntryParser(new ByteArrayInputStream(providedKeySharePairBytes), false);
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);

        assertEquals(expectedKeyShareLength, (int) entry.getPublicKeyLength().getValue());
        assertArrayEquals(expectedKeyShare, entry.getPublicKey().getValue());
        assertArrayEquals(expectedKeyShareType, entry.getGroup().getValue());
    }
}
