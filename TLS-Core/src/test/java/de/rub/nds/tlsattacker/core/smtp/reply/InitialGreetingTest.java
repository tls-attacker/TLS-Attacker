/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.extensions.ATRNExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.HELPExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.STARTTLSExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions._8BITMIMEExtension;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class InitialGreetingTest {

    @Test
    public void testParseSimple() {
        String stringMessage = "220 seal.cs.upb.de says Greetings\r\n";

        SmtpInitialGreeting greeting = new SmtpInitialGreeting();
        //        Parser parser =
        //                greeting.getParser()
        //                        new
        // ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        //        parser.parse(ehlo);
        //        assertEquals(250, ehlo.getReplyCode());
        //        assertEquals("seal.cs.upb.de", ehlo.getDomain());
        //        assertEquals("says Greetings", ehlo.getGreeting());
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
        String stringMessage =
                "250-seal.cs.upb.de says Greetings\r\n"
                        + "250-8BITMIME\r\n"
                        + "250-SIZE 12345678\r\n"
                        + "250-STARTTLS\r\n"
                        + "250 HELP\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        EHLOReplyParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ehlo);
        assertEquals(250, ehlo.getReplyCode());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
        assertEquals("says Greetings", ehlo.getGreeting());
        assertEquals(4, ehlo.getExtensions().size());
        assertEquals("8BITMIME", ehlo.getExtensions().get(0).getEhloKeyword());
        // TODO: Parse the extension parameters
        // assertEquals("SIZE 12345678", ehlo.getExtensions().get(1).getEhloKeyword());
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
        assertEquals(
                "250 seal.cs.upb.de says Greetings\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void serializeWithExtensions() {
        SmtpEHLOReply ehlo = new SmtpEHLOReply();
        ehlo.setReplyCode(250);
        ehlo.setDomain("seal.cs.upb.de");
        ehlo.setGreeting("says Greetings");
        ehlo.setExtensions(
                List.of(
                        new _8BITMIMEExtension(),
                        new ATRNExtension(),
                        new STARTTLSExtension(),
                        new HELPExtension()));

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = ehlo.getPreparator(context);
        Serializer serializer = ehlo.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals(
                "250-seal.cs.upb.de says Greetings\r\n250-8BITMIME\r\n250-ATRN\r\n250-STARTTLS\r\n250 HELP\r\n",
                serializer.getOutputStream().toString());
    }
}
