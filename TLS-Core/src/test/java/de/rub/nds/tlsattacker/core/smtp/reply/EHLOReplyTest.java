/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.extensions.*;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class EHLOReplyTest {

    @Test
    public void testParseSimple() {
        String stringMessage = "250 seal.cs.upb.de says Greetings\r\n";

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
    void testSerializeSimple() {
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
    void testSerializeWithExtensions() {
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

    @Test
    public void testParseMalformedSingleLineReply() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250-seal.upb.de Hello user! itsa me\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        assertThrows(EndOfStreamException.class, () -> parser.parse(reply));
    }

    @Test
    public void testParseMultiLineReplyWithUnknownKeyword() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250-seal.upb.de Hello user! itsa me\r\n250-STARTTLS\r\n250 UNKNOWNKEYWORD\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        assertThrows(ParserException.class, () -> parser.parse(reply));
    }

    @Test
    public void testParseValidMultiLineReply() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250-seal.upb.de Hello user! itsa me\r\n250-STARTTLS\r\n250 HELP\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals("seal.upb.de", reply.getDomain());
        assertEquals("Hello user! itsa me", reply.getGreeting());
        assertEquals(2, reply.getExtensions().size());
        assertTrue(reply.getExtensions().stream().anyMatch(e -> e instanceof STARTTLSExtension));
        assertTrue(reply.getExtensions().stream().anyMatch(e -> e instanceof HELPExtension));
    }

    @Test
    public void testParseCommandNotImplemented() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "502 Command not implemented\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals(502, reply.getReplyCode());
    }

    @Test
    public void testParseMailboxUnavailable() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "550 Requested action not taken: mailbox unavailable\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals(550, reply.getReplyCode());
    }

    @Test
    public void testParseCommandParameterNotImplemented() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "504 Command parameter not implemented\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals(504, reply.getReplyCode());
    }

    @Disabled("Invalid test case")
    @Test
    public void testParseInvalidMultilineError() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "502 Command not implemented\r\n250 Second line for some reason\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals(502, reply.getReplyCode());
        assertEquals("", reply.getDomain());
    }
}
