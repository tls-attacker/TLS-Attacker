/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

abstract class AbstractProtocolMessageParserTest<
        MT extends ProtocolMessage, PT extends ProtocolMessageParser<MT>> {
    private final Function<InputStream, PT> parserConstructor;
    private final BiFunction<InputStream, TlsContext, PT> parserConstructorWithContext;
    protected PT parser;

    protected MT message;

    private final List<Named<Function<MT, Object>>> messageGetters;
    protected final Class<MT> messageClass;

    protected final Config config;
    protected final TlsContext tlsContext;

    AbstractProtocolMessageParserTest(
            Class<MT> messageClass, BiFunction<InputStream, TlsContext, PT> parserConstructor) {
        this(messageClass, parserConstructor, List.of());
    }

    AbstractProtocolMessageParserTest(
            Class<MT> messageClass,
            BiFunction<InputStream, TlsContext, PT> parserConstructorWithContext,
            List<Named<Function<MT, Object>>> messageGetters) {
        this.parserConstructorWithContext = parserConstructorWithContext;
        this.parserConstructor = null;
        this.messageGetters = messageGetters;
        this.config = Config.createConfig();
        this.tlsContext = new TlsContext(config);
        this.messageClass = messageClass;
    }

    AbstractProtocolMessageParserTest(
            Class<MT> messageClass,
            Function<InputStream, PT> parserConstructor,
            List<Named<Function<MT, Object>>> messageGetters) {
        this.parserConstructor = parserConstructor;
        this.parserConstructorWithContext = null;
        this.messageGetters = messageGetters;
        this.config = Config.createConfig();
        this.tlsContext = new TlsContext(config);
        this.messageClass = messageClass;
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testParseTlsMessageContent(
            ProtocolVersion providedProtocolVersion,
            byte[] providedMessageBytes,
            List<Object> expectedMessageSpecificValues) {
        parseTlsMessage(providedProtocolVersion, providedMessageBytes);
        assertMessageSpecific(expectedMessageSpecificValues);
    }

    protected void parseTlsMessage(
            ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes) {
        prepareParsing(providedProtocolVersion, providedMessageBytes);
        parser.parse(message);
    }

    protected void prepareParsing(
            ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes) {
        tlsContext.setLastRecordVersion(providedProtocolVersion);
        tlsContext.setSelectedProtocolVersion(providedProtocolVersion);
        getParser(providedProtocolVersion, providedMessageBytes);
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
    }

    protected void getParser(ProtocolVersion providedProtocolVersion, byte[] providedMessageBytes) {
        if (parserConstructorWithContext != null) {
            parser =
                    parserConstructorWithContext.apply(
                            getMessageInputStream(providedMessageBytes), tlsContext);
        } else {
            parser = parserConstructor.apply(getMessageInputStream(providedMessageBytes));
        }
    }

    protected ByteArrayInputStream getMessageInputStream(byte[] providedMessageBytes) {
        return new ByteArrayInputStream(providedMessageBytes);
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
