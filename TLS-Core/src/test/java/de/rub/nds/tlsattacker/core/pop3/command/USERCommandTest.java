package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3USERCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class USERCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        USERCommand userCommand = new USERCommand();
        String message = "USER juan.fernandez\r\n";

        Pop3USERCommandParser parser = userCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(userCommand);

        assertEquals(userCommand.getUsername(), "juan.fernandez");
        assertEquals(userCommand.getCommandName(), "USER");
    }
}
