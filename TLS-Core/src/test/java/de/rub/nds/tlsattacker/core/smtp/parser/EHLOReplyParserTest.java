/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.extensions.HELPExtension;
import de.rub.nds.tlsattacker.core.smtp.extensions.STARTTLSExtension;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class EHLOReplyParserTest {

    @Test
    public void testSingleLineReply() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250 seal.upb.de\r\n".getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals(reply.getDomain(), "seal.upb.de");
        assertNull(reply.getGreeting());
        assertTrue(reply.getExtensions().isEmpty());
    }

    @Test
    public void testSingleLineReplyWithGreeting() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250 seal.upb.de Hello user! itsa me\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        parser.parse(reply);
        assertEquals("seal.upb.de", reply.getDomain());
        assertEquals("Hello user! itsa me", reply.getGreeting());
        assertTrue(reply.getExtensions().isEmpty());
    }

    @Test
    public void testMalformedSingleLineReply() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250-seal.upb.de Hello user! itsa me\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        assertThrows(ParserException.class, () -> parser.parse(reply));
    }

    @Test
    public void testMultiLineReplyWithUnknownKeyword() {
        EHLOReplyParser parser =
                new EHLOReplyParser(
                        new ByteArrayInputStream(
                                "250-seal.upb.de Hello user! itsa me\r\n250-STARTTLS\r\n250 END\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOReply reply = new SmtpEHLOReply();
        assertThrows(ParserException.class, () -> parser.parse(reply));
    }

    @Test
    public void testValidMultiLineReply() {
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
}
