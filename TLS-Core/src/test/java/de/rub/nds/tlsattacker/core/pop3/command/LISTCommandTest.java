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
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class LISTCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        LISTCommand listCommand = new LISTCommand();
        String message = "LIST\r\n";

        Pop3CommandParser<LISTCommand> parser =
                listCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listCommand);

        assertEquals(listCommand.getCommandName(), "LIST");
        assertFalse(listCommand.hasMessageNumber());
        assertNull(listCommand.getMessageNumber());
    }

    @Test
    void testParseScanListing() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        LISTCommand listCommand = new LISTCommand();
        String message = "LIST 1\r\n";

        Pop3CommandParser<LISTCommand> parser =
                listCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listCommand);

        assertEquals(listCommand.getCommandName(), "LIST");
        assertTrue(listCommand.hasMessageNumber());
        assertEquals(listCommand.getMessageNumber(), 1);
    }
}
