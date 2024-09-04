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
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline.SmtpDATAContentReply;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline.SmtpGenericMultilineReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

public class DATAContentReplyTest {

    @Test
    public void testParse() {
        String[] validReplies = {
            "250 OK\r\n",
            "552 FullMemory\r\n",
            "554 failed\r\n",
            "451 error\r\n",
            "452 fullStorage\r\n",
            "450 Mailboxfull\r\n",
            "550 noMailbox\r\n"
        };

        for (int i = 0; i < validReplies.length; i++) {
            String reply = validReplies[i];

            SmtpGenericReplyParser<SmtpGenericMultilineReply> parser =
                    new SmtpGenericReplyParser<>(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            SmtpDATAContentReply dataContentReply = new SmtpDATAContentReply();
            parser.parse(dataContentReply);
            assertEquals(Integer.parseInt(reply.substring(0, 3)), dataContentReply.getReplyCode());
            assertEquals(reply.substring(4), dataContentReply.getHumanReadableMessages().get(i));
        }
    }

    @Test
    public void testSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAContentReply reply = new SmtpDATAContentReply();
        reply.setReplyCode(250);
        reply.setHumanReadableMessages(List.of("OK"));

        Serializer<?> serializer = reply.getSerializer(context);
        serializer.serialize();

        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }

    // TODO: handler is unused here. should be fixed probably?
    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAContentReply reply = new SmtpDATAContentReply();
        Handler<?> handler = reply.getHandler(context);

        assertTrue(context.getForwardPathBuffer().isEmpty());
        assertTrue(context.getReversePathBuffer().isEmpty());
        assertTrue(context.getMailDataBuffer().isEmpty());
    }
}
