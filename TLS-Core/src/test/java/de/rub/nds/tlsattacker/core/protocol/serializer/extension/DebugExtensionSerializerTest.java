/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.DebugExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class DebugExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                DebugExtensionMessage, DebugExtensionSerializer> {

    public DebugExtensionSerializerTest() {
        super(
                DebugExtensionMessage::new,
                DebugExtensionSerializer::new,
                List.of((msg, obj) -> msg.setDebugContent((String) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return DebugExtensionParserTest.provideTestVectors();
    }
}
