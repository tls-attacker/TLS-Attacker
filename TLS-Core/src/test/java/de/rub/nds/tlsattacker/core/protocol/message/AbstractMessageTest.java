/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

abstract class AbstractMessageTest<T extends ProtocolMessage> {

    protected T message;

    private final String expectedToStringFormat;

    public AbstractMessageTest(Supplier<T> messageConstructor, String expectedToStringFormat) {
        this.message = messageConstructor.get();
        this.expectedToStringFormat = expectedToStringFormat;
    }

    @ParameterizedTest
    @MethodSource("provideToStringTestVectors")
    public void testToString(Object[] values, BiConsumer<T, Object[]> messagePreparator) {
        // Prepare message if a message preparator is provided
        if (messagePreparator != null) {
            messagePreparator.accept(message, values);
        }
        // Convert byte arrays to hex strings (if this isn't done the expected string only contains
        // a reference id)
        for (int i = 0; i < values.length; i++) {
            if (values[i] instanceof byte[]) {
                values[i] = ArrayConverter.bytesToHexString((byte[]) values[i]);
            }
        }
        assertEquals(String.format(expectedToStringFormat, values), message.toString());
    }
}
