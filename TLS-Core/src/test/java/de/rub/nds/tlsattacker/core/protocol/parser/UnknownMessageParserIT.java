/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.io.ByteArrayInputStream;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UnknownMessageParserIT {

    private Config config;

    public void setUp() {
        config = Config.createConfig();
    }

    public static Stream<Arguments> provideTestVectors() {
        Stream.Builder<Arguments> streamBuilder = Stream.builder();
        Random random = new Random(42);
        for (int i = 0; i < 100; i++) {
            byte[] array = new byte[random.nextInt(100)];
            if (array.length > 0) {
                random.nextBytes(array);
            }
            // noinspection PrimitiveArrayArgumentToVarargsMethod
            streamBuilder.add(Arguments.of(array));
        }
        return streamBuilder.build();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testParse(byte[] providedMessageBytes) {
        UnknownMessageParser parser =
                new UnknownMessageParser(new ByteArrayInputStream(providedMessageBytes));
        UnknownMessage message = new UnknownMessage();
        parser.parse(message);
        assertArrayEquals(providedMessageBytes, message.getCompleteResultingMessage().getValue());
    }
}
