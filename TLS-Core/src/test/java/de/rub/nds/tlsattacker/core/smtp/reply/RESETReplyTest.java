package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpRESETReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RESETReplyTest {

    @Test
    void testParse() {
        String message = "250 OK\r\n";

        SmtpRESETReply resetReply = new SmtpRESETReply();
        SmtpGenericReplyParser<SmtpRESETReply> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));

        parser.parse(resetReply);
        assertEquals(250, resetReply.getReplyCode());
        assertEquals("OK", resetReply.getHumanReadableMessage());
    }

    @Test
    public void testSerialize() {
        SmtpRESETReply reply = new SmtpRESETReply();
        reply.setReplyCode(250);
        reply.setHumanReadableMessage("OK");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = reply.getSerializer(context);
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }

}
