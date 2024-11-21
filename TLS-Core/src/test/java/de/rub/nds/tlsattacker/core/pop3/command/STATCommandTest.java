package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class STATCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        STATCommand statCommand = new STATCommand();
        String message = "STAT\r\n";

        Pop3CommandParser<STATCommand> parser = statCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(statCommand);

        assertEquals(statCommand.getCommandName(), "STAT");
    }
}
