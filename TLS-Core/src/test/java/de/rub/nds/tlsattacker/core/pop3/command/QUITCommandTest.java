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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.NOOPCommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.QUITCommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class QUITCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        QUITCommand quitCommand = new QUITCommand();
        String message = "QUIT\r\n";

        Pop3CommandParser<QUITCommand> parser =
                quitCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(quitCommand);

        assertEquals(quitCommand.getCommandName(), "QUIT");
    }

    @Test
    void testSerialize() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        QUITCommand quitCommand = new QUITCommand();
        QUITCommandPreparator preparator = quitCommand.getPreparator(context);
        Pop3MessageSerializer<?> serializer = quitCommand.getSerializer(context);

        preparator.prepare();
        serializer.serialize();

        assertEquals("QUIT\r\n", serializer.getOutputStream().toString());
    }
}
