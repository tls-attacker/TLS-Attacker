package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class DELECommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        DELECommand deleCommand = new DELECommand();
        String message = "DELE 1\r\n";

        Pop3CommandParser<DELECommand> parser = deleCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(deleCommand);

        assertEquals(deleCommand.getMessageNumber(), 1);
        assertEquals(deleCommand.getCommandName(), "DELE");
    }
}
