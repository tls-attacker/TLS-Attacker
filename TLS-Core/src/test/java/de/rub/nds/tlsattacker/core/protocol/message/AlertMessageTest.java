/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.jupiter.params.provider.Arguments;

import java.util.function.BiConsumer;
import java.util.stream.Stream;

public class AlertMessageTest extends AbstractMessageTest<AlertMessage> {

    public AlertMessageTest() {
        super(AlertMessage::new, "AlertMessage:\n" + "  Level: %s\n" + "  Description: %s");
    }

    public static Stream<Arguments> provideToStringTestVectors() {
        BiConsumer<AlertMessage, Object[]> messagePreparator = (AlertMessage message, Object[] values) -> {
            message.setDescription((byte) values[0]);
            message.setLevel((byte) values[1]);
        };
        return Stream.of(Arguments.of(new Object[] { null, null }, null),
            Arguments.of(new Object[] { (byte) 199, (byte) 199 }, messagePreparator));
    }
}
