package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class LISTCommandTest {

    @Test
    void testParse() {
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        LISTCommand listCommand = new LISTCommand();
        String message = "LIST\r\n";

        Pop3CommandParser<LISTCommand> parser = listCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
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

        Pop3CommandParser<LISTCommand> parser = listCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listCommand);

        assertEquals(listCommand.getCommandName(), "LIST");
        assertTrue(listCommand.hasMessageNumber());
        assertEquals(listCommand.getMessageNumber(), 1);
    }
}
