/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3LISTCommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class Pop3LISTCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTCommand listCommand = new Pop3LISTCommand();
        String message = "LIST\r\n";

        Pop3CommandParser<Pop3LISTCommand> parser =
                listCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listCommand);

        assertEquals(listCommand.getCommandName(), "LIST");
        assertFalse(listCommand.hasMessageNumber());
        assertEquals(listCommand.getMessageNumber(), -1);
    }

    @Test
    void testParseScanListing() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTCommand listCommand = new Pop3LISTCommand();
        String message = "LIST 1\r\n";

        Pop3CommandParser<Pop3LISTCommand> parser =
                listCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listCommand);

        assertEquals(listCommand.getCommandName(), "LIST");
        assertTrue(listCommand.hasMessageNumber());
        assertEquals(listCommand.getMessageNumber(), 1);
    }

    @Test
    void testSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTCommand listCommand = new Pop3LISTCommand();
        Pop3LISTCommandPreparator preparator = listCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = listCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("LIST\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testSerializeScanListing() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTCommand listCommand = new Pop3LISTCommand(1);
        Pop3LISTCommandPreparator preparator = listCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = listCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("LIST 1\r\n", serializer.getOutputStream().toString());
    }
}
