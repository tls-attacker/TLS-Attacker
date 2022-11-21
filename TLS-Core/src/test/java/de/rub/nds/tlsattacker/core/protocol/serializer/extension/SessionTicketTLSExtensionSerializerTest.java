/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParserTest;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

public class SessionTicketTLSExtensionSerializerTest extends
    AbstractExtensionMessageSerializerTest<SessionTicketTLSExtensionMessage, SessionTicketTLSExtensionSerializer> {

    public SessionTicketTLSExtensionSerializerTest() {
        super(SessionTicketTLSExtensionMessage::new, SessionTicketTLSExtensionSerializer::new,
            List.of((msg, obj) -> msg.getSessionTicket().setIdentity((byte[]) obj)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return SessionTicketTLSExtensionParserTest.provideTestVectors();
    }
}
