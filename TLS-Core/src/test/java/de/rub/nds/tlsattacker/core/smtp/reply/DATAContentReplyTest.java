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
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.DATAContentReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

public class DATAContentReplyTest {

    @Test
    public void testParse() {
        String stringMessage = "250 OK \r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAContentReply reply = new SmtpDATAContentReply();
        DATAContentReplyParser parser =
                new DATAContentReplyParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(reply);
        assertEquals(250, reply.getReplyCode());
        assertEquals("OK", reply.getReplyLines().get(0));
    }

    @Test
    public void testvalidReplyCode() {
        String[] validReplies = {
            "250 OK\r\n",
            "552 FullMemory\r\n",
            "554 failed\r\n",
            "451 error\r\n",
            "452 fullStorage\r\n",
            "450 Mailboxfull\r\n",
            "550 noMailbox\r\n"
        };
        for (String reply : validReplies) {
            DATAContentReplyParser parser =
                    new DATAContentReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            SmtpDATAContentReply dataContentReply = new SmtpDATAContentReply();
            parser.parse(dataContentReply);
            assertEquals(Integer.parseInt(reply.substring(0, 3)), dataContentReply.getReplyCode());
        }
    }

    @Test
    public void invalidReplyCode() {
        String[] validReplies = {
            "345\r\n", "111\r\n", "390\r\n", "211\r\n", "252\r\n", "421\r\n", "214\r\n"
        };
        for (String reply : validReplies) {
            DATAContentReplyParser parser =
                    new DATAContentReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            SmtpDATAContentReply dataContentReply = new SmtpDATAContentReply();
            assertThrows(ParserException.class, () -> parser.parse(dataContentReply));
        }
    }

    @Test
    public void testSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAContentReply reply = new SmtpDATAContentReply();
        reply.setReplyCode(250);
        reply.setReplyLines(List.of("OK"));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAContentReply reply = new SmtpDATAContentReply();
        Handler handler = reply.getHandler(context);

        assertTrue(context.getForwardPathBuffer().isEmpty());
        assertTrue(context.getReversePathBuffer().isEmpty());
        assertTrue(context.getMailDataBuffer().isEmpty());
    }
}
