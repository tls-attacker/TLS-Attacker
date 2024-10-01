package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RESETCommandTest {

    @Test
    void testParse() {
        String message = "RSET\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRESETCommand resetCommand = new SmtpRESETCommand();
        Parser parser =
                resetCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(resetCommand);
        assertEquals("RSET", resetCommand.getVerb());
    }

    @Test
    void testParseTrailingWhitespace() {
        String message = "RSET \r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRESETCommand resetCommand = new SmtpRESETCommand();
        Parser parser =
                resetCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(resetCommand);
        assertEquals("RSET", resetCommand.getVerb());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRESETCommand resetCommand = new SmtpRESETCommand();
        Serializer serializer = resetCommand.getSerializer(context);
        serializer.serialize();
        assertEquals("RSET\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRESETCommand resetCommand = new SmtpRESETCommand();
        resetCommand.getHandler(context).adjustContext(resetCommand);

        assertTrue(context.getReversePathBuffer().isEmpty());
        assertTrue(context.getForwardPathBuffer().isEmpty());
        assertEquals(context.getMailDataBuffer().size(), 0);
    }
}
