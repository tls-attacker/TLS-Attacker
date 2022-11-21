/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.function.Function;

abstract class AbstractExtensionParserTest<MT extends ExtensionMessage, PT extends ExtensionParser<MT>> {

    private final TriFunction<Integer, byte[], Config, PT> parserConstructor;
    protected PT parser;

    protected MT message;
    private final List<Named<Function<MT, Object>>> messageGetters;

    protected final Config config;

    AbstractExtensionParserTest(TriFunction<Integer, byte[], Config, PT> parserConstructor) {
        this(parserConstructor, List.of());
    }

    AbstractExtensionParserTest(TriFunction<Integer, byte[], Config, PT> parserConstructor,
        List<Named<Function<MT, Object>>> messageGetters) {
        this.parserConstructor = parserConstructor;
        this.messageGetters = messageGetters;
        this.config = Config.createConfig();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testParseExtensionMessageContent(byte[] providedExtensionBytes,
        List<Object> providedAdditionalValues, Object expectedExtensionType, int expectedExtensionLength,
        List<Object> expectedMessageSpecificValues) {
        byte[] expectedExtensionTypeBytes = null;
        if (expectedExtensionType instanceof byte[]) {
            expectedExtensionTypeBytes = (byte[]) expectedExtensionType;
        } else if (expectedExtensionType instanceof ExtensionType) {
            expectedExtensionTypeBytes = ((ExtensionType) expectedExtensionType).getValue();
        } else {
            fail("expectedExtensionType is neither of type byte[] nor ExtensionType");
        }

        parseExtensionMessage(providedExtensionBytes);
        assertExtensionMessageBase(providedExtensionBytes, expectedExtensionTypeBytes, expectedExtensionLength);
        assertExtensionMessageSpecific(providedAdditionalValues, expectedMessageSpecificValues);
    }

    private void parseExtensionMessage(byte[] providedExtensionBytes) {
        parser = parserConstructor.apply(0, providedExtensionBytes, config);
        message = parser.parse();
    }

    private void assertExtensionMessageBase(byte[] expectedExtensionBytes, byte[] expectedExtensionType,
        int expectedExtensionLength) {
        assertArrayEquals(expectedExtensionBytes, message.getExtensionBytes().getValue(),
            "ExtensionMessage::getExtensionBytes");
        assertArrayEquals(expectedExtensionType, message.getExtensionType().getValue(),
            "ExtensionMessage::getExtensionType");
        assertEquals(expectedExtensionLength, message.getExtensionLength().getValue(),
            "ExtensionMessage::getExtensionLength");
    }

    protected void assertExtensionMessageSpecific(List<Object> providedAdditionalValues,
        List<Object> expectedMessageSpecificValues) {
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
