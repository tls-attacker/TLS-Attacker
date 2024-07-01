package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOCommandParser;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.EHLOReplyPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EHLOReplyTest {

    @Test
    public void testParseSimple() {
        String stringMessage = "250 seal.cs.upb.de says Greetings\r\n";

        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        parser.parse(ehlo);
        assertEquals(250, ehlo.getReplyCode());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
        assertEquals("says Greetings", ehlo.getGreeting());
    }
    @Test
    public void testParseSimpleNoGreeting() {
        String stringMessage = "250 seal.cs.upb.de\r\n";

        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        parser.parse(ehlo);
        assertEquals(250, ehlo.getReplyCode());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
        assertNull(ehlo.getGreeting());
    }

    @Test
    public void testParseMultipleLinesWithExtensions() {
        String stringMessage = "250-seal.cs.upb.de says Greetings\r\n" +
                "250-8BITMIME\r\n" +
                "250-SIZE 12345678\r\n" +
                "250-STARTTLS\r\n" +
                "250 HELP\r\n";

        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        parser.parse(ehlo);
        assertEquals(250, ehlo.getReplyCode());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
        assertEquals("says Greetings", ehlo.getGreeting());
        assertEquals(4, ehlo.getExtensions().size());
        assertEquals("8BITMIME", ehlo.getExtensions().get(0).getEhloKeyword());
        //TODO: Parse the extension parameters
        //assertEquals("SIZE 12345678", ehlo.getExtensions().get(1).getEhloKeyword());
        assertEquals("STARTTLS", ehlo.getExtensions().get(2).getEhloKeyword());
        assertEquals("HELP", ehlo.getExtensions().get(3).getEhloKeyword());
    }

    @Test
    void serializeSimple() {
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        ehlo.setReplyCode(250);
        ehlo.setDomain("seal.cs.upb.de");
        ehlo.setGreeting("says Greetings");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = ehlo.getPreparator(context);
        Serializer serializer = ehlo.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250 seal.cs.upb.de says Greetings\r\n", serializer.getOutputStream().toString());
    }
    @Test
    void serializeWithExtensions() {
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        ehlo.setReplyCode(250);
        ehlo.setDomain("seal.cs.upb.de");
        ehlo.setGreeting("says Greetings");
        ehlo.setExtensions(List.of(
                new _8BITMIMEExtension(),
                new ATRNExtension(),
                new STARTTLSExtension(),
                new HELPExtension()
        ));

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = ehlo.getPreparator(context);
        Serializer serializer = ehlo.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250-seal.cs.upb.de says Greetings\r\n250-8BITMIME\r\n250-ATRN\r\n250-STARTTLS\r\n250 HELP\r\n", serializer.getOutputStream().toString());
    }

}