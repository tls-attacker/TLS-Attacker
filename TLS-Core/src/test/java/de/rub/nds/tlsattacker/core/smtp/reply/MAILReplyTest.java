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
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MAILReplyTest {

    @Test
    public void testParse() {
        String stringMessage = "250 OK\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpMAILReply reply = new SmtpMAILReply();
        MAILReplyParser parser =
                reply.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(reply);

        assertEquals(250, reply.getReplyCode());
        assertEquals("OK", reply.getMessage());
    }

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

    @Test
    public void testSerialize() {
        SmtpMAILReply reply = new SmtpMAILReply();
        reply.setReplyCode(250);
        reply.setMessage("OK");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }
}
