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

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

abstract class AbstractExtensionMessageSerializerTest<
        MT extends ExtensionMessage, ST extends ExtensionSerializer<MT>> {

    protected final MT message;

    private final Function<MT, ST> serializerConstructor;
    protected ST serializer;

    private final List<BiConsumer<MT, Object>> messageSetters;

    AbstractExtensionMessageSerializerTest(
            Supplier<MT> messageConstructor, Function<MT, ST> serializerConstructor) {
        this(messageConstructor, serializerConstructor, List.of());
    }

    AbstractExtensionMessageSerializerTest(
            Supplier<MT> messageConstructor,
            Function<MT, ST> serializerConstructor,
            List<BiConsumer<MT, Object>> messageSetters) {
        this.message = messageConstructor.get();
        this.serializerConstructor = serializerConstructor;
        this.messageSetters = messageSetters;
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testSerializeExtensionMessageContent(
            byte[] expectedExtensionBytes,
            List<Object> providedAdditionalValues,
            Object providedExtensionType,
            int providedExtensionLength,
            List<Object> providedMessageSpecificValues) {
        setExtensionMessageBase(providedExtensionType, providedExtensionLength);
        setExtensionMessageSpecific(providedAdditionalValues, providedMessageSpecificValues);
        serializer = serializerConstructor.apply(message);
        message.setExtensionContent(serializer.serializeExtensionContent());
        assertArrayEquals(expectedExtensionBytes, serializer.serialize());
    }

    private void setExtensionMessageBase(
            Object providedExtensionType, int providedExtensionLength) {
        // Unpack ExtensionType to byte[] value
        if (providedExtensionType instanceof ExtensionType) {
            providedExtensionType = ((ExtensionType) providedExtensionType).getValue();
        }
        message.setExtensionType((byte[]) providedExtensionType);
        message.setExtensionLength(providedExtensionLength);
    }

    protected void setExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> providedMessageSpecificValues) {
        for (int i = 0; i < messageSetters.size(); i++) {
            messageSetters.get(i).accept(message, providedMessageSpecificValues.get(i));
        }
    }
}
