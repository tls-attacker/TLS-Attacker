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
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpMAILReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MAILReplyTest {

    @Test
    public void testParse() {
        String stringMessage = "250 OK\r\n";

        SmtpMAILReply reply = new SmtpMAILReply();
        SmtpGenericReplyParser<SmtpMAILReply> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(reply);
        assertEquals(250, reply.getReplyCode());
        assertEquals("OK", reply.getHumanReadableMessage());
    }

    @Test
    public void testValidReplyCode() {
        SmtpGenericReplyParser<SmtpMAILReply> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(
                                "552 Aborted\r\n".getBytes(StandardCharsets.UTF_8)));

        SmtpMAILReply reply = new SmtpMAILReply();
        parser.parse(reply);
        assertEquals(reply.getReplyCode(), 552);
        assertEquals(reply.getHumanReadableMessage(), "Aborted");
    }

    @Test
    public void testSerialize() {
        SmtpMAILReply reply = new SmtpMAILReply();
        reply.setReplyCode(250);
        reply.setHumanReadableMessage("OK");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = reply.getSerializer(context);
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }
}
