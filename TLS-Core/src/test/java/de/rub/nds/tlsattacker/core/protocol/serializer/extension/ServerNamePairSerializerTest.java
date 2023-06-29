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

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerNamePairParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNamePairPreparator;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ServerNamePairSerializerTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    public static Stream<Arguments> provideTestVectors() {
        return ServerNamePairParserTest.provideTestVectors();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedServerNamePairBytes,
            byte providedServerNameType,
            int providedServerNameLength,
            byte[] providedServerName) {
        ServerNamePair pair = new ServerNamePair(providedServerNameType, providedServerName);
        new ServerNamePairPreparator(context.getChooser(), pair).prepare();
        byte[] actualBytes = new ServerNamePairSerializer(pair).serialize();
        assertArrayEquals(expectedServerNamePairBytes, actualBytes);
    }
}
