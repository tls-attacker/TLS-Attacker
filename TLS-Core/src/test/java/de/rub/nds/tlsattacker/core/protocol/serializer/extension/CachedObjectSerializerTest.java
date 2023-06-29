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

import de.rub.nds.tlsattacker.core.constants.CachedInfoType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CachedObjectParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedObjectPreparator;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CachedObjectSerializerTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    public static Stream<Arguments> provideTestVectors() {
        return CachedObjectParserTest.provideTestVectors();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedCachedObjectBytes,
            ConnectionEndType providedSpeakingEndType,
            CachedInfoType providedCachedInfoType,
            Integer providedHashLength,
            byte[] providedHash) {
        CachedObject object =
                new CachedObject(
                        providedCachedInfoType.getValue(), providedHashLength, providedHash);
        CachedObjectPreparator preparator =
                new CachedObjectPreparator(context.getChooser(), object);
        preparator.prepare();

        CachedObjectSerializer serializer = new CachedObjectSerializer(object);
        assertArrayEquals(expectedCachedObjectBytes, serializer.serialize());
    }
}
