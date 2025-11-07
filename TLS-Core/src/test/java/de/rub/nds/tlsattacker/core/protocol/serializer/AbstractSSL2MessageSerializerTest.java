/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

abstract class AbstractSSL2MessageSerializerTest<
        MT extends SSL2Message, ST extends SSL2MessageSerializer<MT>> {

    private final MT message;

    private final Function<MT, ST> serializerConstructor;
    private final BiFunction<MT, ProtocolVersion, ST> serializerConstructorWithVersion;
    protected ST serializer;

    private final List<BiConsumer<MT, Object>> messageSetters;

    AbstractSSL2MessageSerializerTest(
            Supplier<MT> messageConstructor,
            Function<MT, ST> serializerConstructor,
            List<BiConsumer<MT, Object>> messageSetters) {
        this.message = messageConstructor.get();
        this.serializerConstructor = serializerConstructor;
        this.serializerConstructorWithVersion = null;
        this.messageSetters = messageSetters;
    }

    AbstractSSL2MessageSerializerTest(
            Supplier<MT> messageConstructor,
            BiFunction<MT, ProtocolVersion, ST> serializerConstructorWithVersion,
            List<BiConsumer<MT, Object>> messageSetters) {
        this.message = messageConstructor.get();
        this.serializerConstructorWithVersion = serializerConstructorWithVersion;
        this.serializerConstructor = null;
        this.messageSetters = messageSetters;
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testSerializeTlsMessageContent(
            ProtocolVersion providedProtocolVersion,
            byte[] expectedMessageBytes,
            List<Object> providedMessageSpecificValues) {
        setMessageSpecific(providedMessageSpecificValues);
        if (serializerConstructorWithVersion != null) {
            serializer = serializerConstructorWithVersion.apply(message, providedProtocolVersion);
        } else {
            serializer = serializerConstructor.apply(message);
        }

        assertArrayEquals(expectedMessageBytes, serializer.serialize());
    }

    protected void setMessageSpecific(List<Object> providedMessageSpecificValues) {
        for (int i = 0; i < messageSetters.size(); i++) {
            messageSetters.get(i).accept(message, providedMessageSpecificValues.get(i));
        }
    }
}
