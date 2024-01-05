/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class TokenBindingExtensionSerializerTest
        extends AbstractExtensionMessageSerializerTest<
                TokenBindingExtensionMessage, TokenBindingExtensionSerializer> {

    public TokenBindingExtensionSerializerTest() {
        super(
                TokenBindingExtensionMessage::new,
                TokenBindingExtensionSerializer::new,
                List.of(
                        (msg, obj) -> msg.setTokenBindingVersion((byte[]) obj),
                        (msg, obj) -> msg.setParameterListLength((Integer) obj),
                        (msg, obj) -> msg.setTokenBindingKeyParameters((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return TokenBindingExtensionParserTest.provideTestVectors();
    }
}
