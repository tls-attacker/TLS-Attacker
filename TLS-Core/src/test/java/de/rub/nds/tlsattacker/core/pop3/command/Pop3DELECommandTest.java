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
import de.rub.nds.tlsattacker.core.pop3.preparator.command.DELECommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class Pop3DELECommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3DELECommand deleCommand = new Pop3DELECommand();
        String message = "DELE 1\r\n";

        Pop3CommandParser<Pop3DELECommand> parser =
                deleCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(deleCommand);

        assertEquals(deleCommand.getMessageNumber(), 1);
        assertEquals(deleCommand.getCommandName(), "DELE");
    }

    @Test
    void testSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3DELECommand deleCommand = new Pop3DELECommand(1);
        DELECommandPreparator preparator = deleCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = deleCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("DELE 1\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testDefaultSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3DELECommand deleCommand = new Pop3DELECommand();
        DELECommandPreparator preparator = deleCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = deleCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("DELE 1\r\n", serializer.getOutputStream().toString());
    }
}
