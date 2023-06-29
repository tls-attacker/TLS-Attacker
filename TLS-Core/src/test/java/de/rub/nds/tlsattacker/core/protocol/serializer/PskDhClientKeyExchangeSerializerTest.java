/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDhClientKeyExchangeParserTest;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.provider.Arguments;

public class PskDhClientKeyExchangeSerializerTest
        extends AbstractHandshakeMessageSerializerTest<
                PskDhClientKeyExchangeMessage, PskDhClientKeyExchangeSerializer> {

    public PskDhClientKeyExchangeSerializerTest() {
        super(
                PskDhClientKeyExchangeMessage::new,
                PskDhClientKeyExchangeSerializer::new,
                List.of(
                        (msg, obj) -> msg.setIdentityLength((Integer) obj),
                        (msg, obj) -> msg.setIdentity((byte[]) obj),
                        (msg, obj) -> msg.setPublicKeyLength((Integer) obj),
                        (msg, obj) -> msg.setPublicKey((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return PskDhClientKeyExchangeParserTest.provideTestVectors();
    }
}
