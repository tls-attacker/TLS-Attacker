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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientEsniInnerPreparator;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ClientEsniInnerSerializerTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                        List.of(
                                new ServerNamePair(
                                        (byte) 0x00,
                                        "baz.example.com".getBytes(StandardCharsets.UTF_8)))));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(byte[] expectedBytes, List<ServerNamePair> providedServerNamePairs) {
        ClientEsniInner clientEsniInner = new ClientEsniInner();
        clientEsniInner.setServerNameList(providedServerNamePairs);

        new ClientEsniInnerPreparator(context.getChooser(), clientEsniInner).prepare();
        byte[] actualBytes = new ClientEsniInnerSerializer(clientEsniInner).serialize();
        assertArrayEquals(expectedBytes, actualBytes);
    }
}
