/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.QuadFunction;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.function.Function;

abstract class AbstractTlsMessageParserTest<MT extends TlsMessage, PT extends TlsMessageParser<MT>> {
    private final QuadFunction<Integer, byte[], ProtocolVersion, Config, PT> parserConstructor;
    protected PT parser;

    protected MT message;

    private final List<Named<Function<MT, Object>>> messageGetters;

    protected final Config config;

    AbstractTlsMessageParserTest(QuadFunction<Integer, byte[], ProtocolVersion, Config, PT> parserConstructor) {
        this(parserConstructor, List.of());
    }

    AbstractTlsMessageParserTest(QuadFunction<Integer, byte[], ProtocolVersion, Config, PT> parserConstructor,
        List<Named<Function<MT, Object>>> messageGetters) {
        this.parserConstructor = parserConstructor;
        this.messageGetters = messageGetters;
        this.config = Config.createConfig();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testParseTlsMessageContent(ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes,
        List<Object> expectedMessageSpecificValues) {
        parseTlsMessage(providedProtocolVersion, providedMessageBytes);
        assertMessageBase(providedMessageBytes);
        assertMessageSpecific(expectedMessageSpecificValues);
    }

    private void parseTlsMessage(ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes) {
        parser = parserConstructor.apply(0, providedMessageBytes, providedProtocolVersion, config);
        message = parser.parse();
    }

    private void assertMessageBase(byte[] expectedMessageBytes) {
        assertArrayEquals(expectedMessageBytes, message.getCompleteResultingMessage().getValue(),
            "TlsMessage::getCompleteResultingMessage");
    }

    protected void assertMessageSpecific(List<Object> expectedMessageSpecificValues) {
        Named<Function<MT, Object>> getter;
        Object expected;
        Object actual;
        for (int i = 0; i < messageGetters.size(); i++) {
            getter = messageGetters.get(i);
            expected = expectedMessageSpecificValues.get(i);
            actual = getter.getPayload().apply(message);
            // Unpack ModifiableVariable fields
            if (actual instanceof ModifiableVariable) {
                actual = ((ModifiableVariable<?>) actual).getValue();
            }
            // Perform assertion
            String assertionMessage = this.getClass().getSimpleName() + " failed: " + getter.getName();
            if (expected instanceof byte[]) {
                assertArrayEquals((byte[]) expected, (byte[]) actual, assertionMessage);
            } else if (expected == null) {
                assertNull(actual, assertionMessage);
            } else {
                assertEquals(expected, actual, assertionMessage);
            }
        }
    }
}
