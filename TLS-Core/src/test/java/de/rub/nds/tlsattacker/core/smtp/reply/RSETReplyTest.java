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

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class RSETReplyTest {

    @Test
    void testParse() {
        String message = "250 OK\r\n";

        SmtpRSETReply resetReply = new SmtpRSETReply();
        SmtpGenericReplyParser<SmtpRSETReply> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));

        parser.parse(resetReply);
        assertEquals(250, resetReply.getReplyCode());
        assertEquals("OK", resetReply.getHumanReadableMessage());
    }

    @Test
    public void testSerialize() {
        SmtpRSETReply reply = new SmtpRSETReply();
        reply.setReplyCode(250);
        reply.setHumanReadableMessage("OK");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = reply.getSerializer(context);
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }
}
