/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SessionTicketTLSExtensionParserTest
        extends AbstractExtensionParserTest<
                SessionTicketTLSExtensionMessage, SessionTicketTLSExtensionParser> {

    public SessionTicketTLSExtensionParserTest() {
        super(
                SessionTicketTLSExtensionMessage.class,
                (stream, context) ->
                        new SessionTicketTLSExtensionParser(stream, new Config(), context),
                List.of(
                        Named.of(
                                "SessionTicketTLSExtensionMessage::getSessionTicket::getIdentity",
                                msg -> msg.getSessionTicket().getIdentity())));
    }

    public static Stream<Arguments> provideTestVectors() {
        byte[] nullArray = null;
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("00230000"),
                        List.of(),
                        ExtensionType.SESSION_TICKET,
                        0,
                        Arrays.asList(nullArray)));
    }
}
