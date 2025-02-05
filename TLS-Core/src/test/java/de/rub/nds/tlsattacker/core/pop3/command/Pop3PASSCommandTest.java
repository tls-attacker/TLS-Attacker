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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3PASSCommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.PASSCommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class Pop3PASSCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3PASSCommand passCommand = new Pop3PASSCommand();
        String message = "PASS p4ssw0rd\r\n";

        Pop3PASSCommandParser parser =
                passCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(passCommand);

        assertEquals(passCommand.getPassword(), "p4ssw0rd");
        assertEquals(passCommand.getCommandName(), "PASS");
    }

    @Test
    void testSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3PASSCommand passCommand = new Pop3PASSCommand("qwertzuiop");
        PASSCommandPreparator preparator = passCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = passCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("PASS qwertzuiop\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testDefaultSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3PASSCommand passCommand = new Pop3PASSCommand();
        PASSCommandPreparator preparator = passCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = passCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        // default password set in config
        assertEquals("PASS s34l-p4ssw0rd!!\r\n", serializer.getOutputStream().toString());
    }
}
