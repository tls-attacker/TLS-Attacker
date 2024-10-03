package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpAUTHReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AUTHReplyTest {

    @Test
    public void testParseSimple() {
        String stringMessage = "235 Authentication successful\r\n";

        SmtpAUTHReply auth = new SmtpAUTHReply();
        SmtpGenericReplyParser<SmtpAUTHReply> parser =
                new SmtpGenericReplyParser<>(new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(auth);

        assertEquals(235, auth.getReplyCode());
        assertEquals("Authentication successful", auth.getHumanReadableMessage());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHReply authReply = new SmtpAUTHReply();
        authReply.setReplyCode(235);
        authReply.setHumanReadableMessage("bla bla");

        Serializer<?> serializer = authReply.getSerializer(context);
        serializer.serialize();
        assertEquals(
                "235 bla bla\r\n",
                serializer.getOutputStream().toString());
    }
}
