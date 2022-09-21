/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Supplier;

abstract class AbstractTlsMessageSerializerTest<MT extends TlsMessage, ST extends TlsMessageSerializer<MT>> {

    private final MT message;

    private final BiFunction<MT, ProtocolVersion, ST> serializerConstructor;
    protected ST serializer;

    private final List<BiConsumer<MT, Object>> messageSetters;

    AbstractTlsMessageSerializerTest(Supplier<MT> messageConstructor,
        BiFunction<MT, ProtocolVersion, ST> serializerConstructor) {
        this(messageConstructor, serializerConstructor, List.of());
    }

    AbstractTlsMessageSerializerTest(Supplier<MT> messageConstructor,
        BiFunction<MT, ProtocolVersion, ST> serializerConstructor, List<BiConsumer<MT, Object>> messageSetters) {
        this.message = messageConstructor.get();
        this.serializerConstructor = serializerConstructor;
        this.messageSetters = messageSetters;
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testSerializeTlsMessageContent(ProtocolVersion providedProtocolVersion,
        byte[] expectedMessageBytes, List<Object> providedMessageSpecificValues) {
        setMessageSpecific(providedMessageSpecificValues);
        serializer = serializerConstructor.apply(message, providedProtocolVersion);
        assertArrayEquals(expectedMessageBytes, serializer.serialize());
    }

    protected void setMessageSpecific(List<Object> providedMessageSpecificValues) {
        for (int i = 0; i < messageSetters.size(); i++) {
            messageSetters.get(i).accept(message, providedMessageSpecificValues.get(i));
        }
    }
}
