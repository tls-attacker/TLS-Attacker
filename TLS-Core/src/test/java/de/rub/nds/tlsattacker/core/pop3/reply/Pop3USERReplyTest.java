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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.USERReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pop3USERReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3USERReply user = new Pop3USERReply();
        user.setStatusIndicator("+OK");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = user.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK user ok\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3USERReply user = new Pop3USERReply();
        USERReplyParser parser =
                user.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(user);

        assertEquals("+OK", user.getStatusIndicator());
        assertEquals("user ok", user.getHumanReadableMessage());
    }

    @Test
    public void parseInvalidReply() {
        String reply = "-ERR user not ok\r\n";
        Pop3USERReply noop = new Pop3USERReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        USERReplyParser parser =
                noop.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
        assertDoesNotThrow(() -> parser.parse(noop));
        assertEquals("-ERR", noop.getStatusIndicator());
        assertEquals("user not ok", noop.getHumanReadableMessage());
    }
}
