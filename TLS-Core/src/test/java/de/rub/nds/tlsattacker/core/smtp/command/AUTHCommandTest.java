package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AUTHCommandTest {

    @Test
    void testParseBasic() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand();
        String stringMessage = "AUTH PLAIN qweqweqwe==\r\n";

        AUTHCommandParser parser =
                auth.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(auth);
        assertEquals("AUTH", auth.getVerb());
        assertEquals("PLAIN", auth.getSaslMechanism());
        assertEquals("qweqweqwe==", auth.getInitialResponse());
    }

    @Test
    void testParseInvalid() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand();
        String stringMessage = "AUTH\r\n";

        AUTHCommandParser parser =
                auth.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        assertThrows(ParserException.class, () -> parser.parse(auth));
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand("PLAIN", "qweqweqwe==");

        Preparator<?> preparator = auth.getPreparator(context);
        Serializer<?> serializer = auth.getSerializer(context);
        preparator.prepare();
        serializer.serialize();

        assertEquals("AUTH PLAIN qweqweqwe==\r\n", serializer.getOutputStream().toString());
    }
}
