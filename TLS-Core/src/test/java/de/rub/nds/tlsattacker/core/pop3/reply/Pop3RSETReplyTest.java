/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.RSETReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pop3RSETReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3RSETReply reset = new Pop3RSETReply();
        reset.setStatusIndicator("+OK");
        reset.setHumanReadableMessage("maildrop has 2 messages (320 octets)");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = reset.getSerializer(context);
        serializer.serialize();

        assertEquals(
                "+OK maildrop has 2 messages (320 octets)\r\n",
                serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK maildrop has 2 messages (320 octets)\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3RSETReply reset = new Pop3RSETReply();
        RSETReplyParser parser =
                reset.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(reset);

        assertEquals("+OK", reset.getStatusIndicator());
        assertEquals("maildrop has 2 messages (320 octets)", reset.getHumanReadableMessage());
    }

    @Test
    public void parseInvalidReply() {
        String reply = "-ERR not ok\r\n";
        Pop3RSETReply reset = new Pop3RSETReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        RSETReplyParser parser =
                reset.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
        assertDoesNotThrow(() -> parser.parse(reset));
        assertEquals("-ERR", reset.getStatusIndicator());
        assertEquals("not ok", reset.getHumanReadableMessage());
    }
}
