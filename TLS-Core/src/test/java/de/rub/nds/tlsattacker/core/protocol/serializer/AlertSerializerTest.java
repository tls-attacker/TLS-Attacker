/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class AlertSerializerTest
        extends AbstractProtocolMessageSerializerTest<AlertMessage, AlertSerializer> {

    public AlertSerializerTest() {
        super(
                AlertMessage::new,
                AlertSerializer::new,
                List.of(
                        (msg, obj) -> msg.setLevel((Byte) obj),
                        (msg, obj) -> msg.setDescription((Byte) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return AlertParserTest.provideTestVectors();
    }
}
