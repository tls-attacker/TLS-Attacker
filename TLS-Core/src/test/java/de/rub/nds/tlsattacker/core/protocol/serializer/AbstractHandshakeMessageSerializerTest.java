/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

abstract class AbstractHandshakeMessageSerializerTest<
                MT extends HandshakeMessage, ST extends HandshakeMessageSerializer<MT>>
        extends AbstractProtocolMessageSerializerTest<MT, ST> {

    AbstractHandshakeMessageSerializerTest(
            Supplier<MT> messageConstructor, Function<MT, ST> serializerConstructor) {
        this(messageConstructor, serializerConstructor, List.of());
    }

    AbstractHandshakeMessageSerializerTest(
            Supplier<MT> messageConstructor,
            Function<MT, ST> serializerConstructor,
            List<BiConsumer<MT, Object>> messageSetters) {
        super(
                messageConstructor,
                serializerConstructor,
                addHandshakeMessageSetters(messageSetters));
    }

    AbstractHandshakeMessageSerializerTest(
            Supplier<MT> messageConstructor,
            BiFunction<MT, ProtocolVersion, ST> serializerConstructor,
            List<BiConsumer<MT, Object>> messageSetters) {
        super(
                messageConstructor,
                serializerConstructor,
                addHandshakeMessageSetters(messageSetters));
    }

    private static <MT extends HandshakeMessage>
            List<BiConsumer<MT, Object>> addHandshakeMessageSetters(
                    List<BiConsumer<MT, Object>> messageSetters) {
        return Stream.concat(
                        Stream.of(
                                (msg, obj) -> msg.setType((Byte) obj),
                                (msg, obj) -> {
                                    if (obj != null) {
                                        msg.setLength((Integer) obj);
                                    }
                                }),
                        messageSetters.stream())
                .collect(Collectors.toUnmodifiableList());
    }
}
