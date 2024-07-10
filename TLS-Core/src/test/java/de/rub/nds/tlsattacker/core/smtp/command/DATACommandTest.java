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
import static org.junit.jupiter.api.Assertions.*;

public class DATACommandTest {
    @Test
    void testParse() {
        String message = "DATA\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATACommand dataCommand = new SmtpDATACommand();
        Parser parser = dataCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(dataCommand);
        assertEquals("DATA", dataCommand.getVerb());
    }

    @Test
    void testParseTrailingWhitespace() {
        String message = "DATA \r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATACommand dataCommand = new SmtpDATACommand();
        Parser parser = dataCommand.getParser(context, new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(dataCommand);
        assertEquals("DATA", dataCommand.getVerb());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATACommand dataCommand = new SmtpDATACommand();
        Serializer serializer = dataCommand.getSerializer(context);
        serializer.serialize();
        assertEquals("DATA\r\n", serializer.getOutputStream().toString());
    }

}
