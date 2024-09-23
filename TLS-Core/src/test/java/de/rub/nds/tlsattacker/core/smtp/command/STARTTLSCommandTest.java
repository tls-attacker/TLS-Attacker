package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class STARTTLSCommandTest {
    @Test
    void testParse() {
        String stringMessage = "STARTTLS\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpSTARTTLSCommand starttlsCommand = new SmtpSTARTTLSCommand();
        Parser parser =
                starttlsCommand.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(starttlsCommand);
        assertEquals("STARTTLS", starttlsCommand.getVerb());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpSTARTTLSCommand starttlsCommand = new SmtpSTARTTLSCommand();
        Preparator preparator = starttlsCommand.getPreparator(context);
        Serializer serializer = starttlsCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("STARTTLS\r\n", serializer.getOutputStream().toString());
    }
}
