/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeySharePairParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class KeySharePairSerializerTest {

    public static Stream<Arguments> provideTestVectors() {
        return KeySharePairParserTest.provideTestVectors();
    }

    /** Test of serializeBytes method, of class KeyShareEntrySerializer. */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedKeySharePairBytes,
            int providedKeyShareLength,
            byte[] providedKeyShare,
            byte[] providedKeyShareType) {
        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroup(providedKeyShareType);
        entry.setPublicKeyLength(providedKeyShareLength);
        entry.setPublicKey(providedKeyShare);
        byte[] actualBytes = new KeyShareEntrySerializer(entry).serialize();
        assertArrayEquals(expectedKeySharePairBytes, actualBytes);
    }
}
