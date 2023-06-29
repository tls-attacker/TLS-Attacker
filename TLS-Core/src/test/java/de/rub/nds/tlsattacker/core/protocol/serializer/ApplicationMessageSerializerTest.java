/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class ApplicationMessageSerializerTest
        extends AbstractProtocolMessageSerializerTest<
                ApplicationMessage, ApplicationMessageSerializer> {

    public ApplicationMessageSerializerTest() {
        super(
                ApplicationMessage::new,
                ApplicationMessageSerializer::new,
                List.of((msg, obj) -> msg.setData((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return ApplicationMessageParserTest.provideTestVectors();
    }
}
