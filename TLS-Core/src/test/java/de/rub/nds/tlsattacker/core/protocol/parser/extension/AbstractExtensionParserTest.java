/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

abstract class AbstractExtensionParserTest<
        MT extends ExtensionMessage, PT extends ExtensionParser<MT>> {

    private final BiFunction<InputStream, TlsContext, PT> parserConstructor;
    protected PT parser;

    protected MT message;
    private final List<Named<Function<MT, Object>>> messageGetters;
    private final Class<MT> messageClass;

    protected final Config config;
    protected final TlsContext tlsContext;

    AbstractExtensionParserTest(
            Class<MT> messageClass, BiFunction<InputStream, TlsContext, PT> parserConstructor) {
        this(messageClass, parserConstructor, List.of());
    }

    AbstractExtensionParserTest(
            Class<MT> messageClass,
            BiFunction<InputStream, TlsContext, PT> parserConstructor,
            List<Named<Function<MT, Object>>> messageGetters) {
        this.parserConstructor = parserConstructor;
        this.messageGetters = messageGetters;
        this.config = new Config();
        this.tlsContext = new TlsContext(config);
        this.messageClass = messageClass;
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testParseExtensionMessageContent(
            byte[] providedExtensionBytes,
            List<Object> providedAdditionalValues,
            Object expectedExtensionType,
            int expectedExtensionLength,
            List<Object> expectedMessageSpecificValues) {
        byte[] expectedExtensionTypeBytes = null;
        if (expectedExtensionType instanceof byte[]) {
            expectedExtensionTypeBytes = (byte[]) expectedExtensionType;
        } else if (expectedExtensionType instanceof ExtensionType) {
            expectedExtensionTypeBytes = ((ExtensionType) expectedExtensionType).getValue();
        } else {
            fail("expectedExtensionType is neither of type byte[] nor ExtensionType");
        }
        providedExtensionBytes =
                Arrays.copyOfRange(
                        providedExtensionBytes,
                        ExtensionByteLength.TYPE + ExtensionByteLength.EXTENSIONS_LENGTH,
                        providedExtensionBytes.length);

        if (providedAdditionalValues.contains(ConnectionEndType.SERVER)) {
            tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        } else {
            tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        }

        parseExtensionMessage(providedExtensionBytes);
        assertExtensionMessageSpecific(providedAdditionalValues, expectedMessageSpecificValues);
    }

    private void parseExtensionMessage(byte[] providedExtensionBytes) {
        parser =
                parserConstructor.apply(
                        new ByteArrayInputStream(providedExtensionBytes), tlsContext);
        if (message == null) {
            try {
                message = messageClass.getConstructor().newInstance();
            } catch (InvocationTargetException
                    | IllegalArgumentException
                    | IllegalAccessException
                    | InstantiationException
                    | NoSuchMethodException
                    | SecurityException ex) {
                fail("Failed to create message instance for " + messageClass.getName());
            }
        }
        parser.parse(message);
    }

    protected void assertExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> expectedMessageSpecificValues) {
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
            String assertionMessage =
                    this.getClass().getSimpleName() + " failed: " + getter.getName();
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
