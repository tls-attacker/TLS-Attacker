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
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.extensions.Smtp8BITMIMEExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpATRNExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpHELPExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpSTARTTLSExtension;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpEHLOReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

// TODO: this doesn't seem to actually test the InitialGreeting class

class InitialGreetingTest {

    @Test
    public void testParseSimpleNoGreeting() {
        String stringMessage = "250 seal.cs.upb.de\r\n";

        SmtpEHLOReplyParser parser =
                new SmtpEHLOReplyParser(
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
        SmtpEHLOReplyParser parser =
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
        Serializer<?> serializer = ehlo.getSerializer(context);
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
                        new Smtp8BITMIMEExtension(),
                        new SmtpATRNExtension(),
                        new SmtpSTARTTLSExtension(),
                        new SmtpHELPExtension()));

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = ehlo.getSerializer(context);
        serializer.serialize();
        assertEquals(
                "250-seal.cs.upb.de says Greetings\r\n250-8BITMIME\r\n250-ATRN\r\n250-STARTTLS\r\n250 HELP\r\n",
                serializer.getOutputStream().toString());
    }
}
