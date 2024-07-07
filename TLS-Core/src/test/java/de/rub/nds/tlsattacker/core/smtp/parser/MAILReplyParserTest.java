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
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpMAILReply;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MAILReplyParserTest {

    @Test
    public void testValidReplyCode() {
        MAILReplyParser parser =
                new MAILReplyParser(
                        new ByteArrayInputStream(
                                "552 Aborted\r\n".getBytes(StandardCharsets.UTF_8)));
        SmtpMAILReply reply = new SmtpMAILReply();
        parser.parse(reply);
        assertEquals(reply.getReplyCode(), 552);
        assertEquals(reply.getMessage(), "Aborted");
    }

    @Test
    public void testInValidReplyCode() {
        MAILReplyParser parser =
                new MAILReplyParser(
                        new ByteArrayInputStream(
                                "111 Aborted\r\n".getBytes(StandardCharsets.UTF_8)));
        SmtpMAILReply reply = new SmtpMAILReply();
        assertThrows(ParserException.class, () -> parser.parse(reply));
    }

    @Test
    public void testMalformedReply() {
        MAILReplyParser parser =
                new MAILReplyParser(
                        new ByteArrayInputStream(
                                "552Aborted\r\n".getBytes(StandardCharsets.UTF_8)));
        SmtpMAILReply reply = new SmtpMAILReply();
        assertThrows(ParserException.class, () -> parser.parse(reply));
    }
}
