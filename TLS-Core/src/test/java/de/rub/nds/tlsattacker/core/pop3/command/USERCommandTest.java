/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3USERCommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.USERCommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class USERCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        USERCommand userCommand = new USERCommand();
        String message = "USER juan.fernandez\r\n";

        Pop3USERCommandParser parser =
                userCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(userCommand);

        assertEquals(userCommand.getUsername(), "juan.fernandez");
        assertEquals(userCommand.getCommandName(), "USER");
    }

    @Test
    void testSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        USERCommand userCommand = new USERCommand("juan.fernandez@upb.de");
        USERCommandPreparator preparator = userCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = userCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("USER juan.fernandez@upb.de\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testDefaultSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        USERCommand userCommand = new USERCommand();
        USERCommandPreparator preparator = userCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = userCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("USER seal@upb.de\r\n", serializer.getOutputStream().toString());
    }
}
