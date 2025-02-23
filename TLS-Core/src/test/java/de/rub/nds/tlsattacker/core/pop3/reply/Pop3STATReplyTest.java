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
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3STATReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pop3STATReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3STATReply stat = new Pop3STATReply();
        stat.setStatusIndicator("+OK");
        stat.setNumberOfMessages(2);
        stat.setMailDropSize(320);

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = stat.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK 2 320\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK 2 320\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3STATReply stat = new Pop3STATReply();
        Pop3STATReplyParser parser =
                stat.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(stat);

        assertEquals("+OK", stat.getStatusIndicator());
        assertEquals(2, stat.getNumberOfMessages());
        assertEquals(320, stat.getMailDropSize());
    }

    @Test
    public void parseInvalidReply() {
        String reply = "-ERR no Info\r\n";
        Pop3STATReply stat = new Pop3STATReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        Pop3STATReplyParser parser =
                stat.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(stat));
        assertEquals(stat.getStatusIndicator(), "-ERR");
        assertEquals(stat.getHumanReadableMessage(), "no Info");
    }

    @Test
    public void parseInvalidOKReply() {
        // This test case is invalid because positive status requires message information to be
        // present.
        String reply = "+OK no Info\r\n";
        Pop3STATReply stat = new Pop3STATReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        Pop3STATReplyParser parser =
                stat.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertThrows(ParserException.class, () -> parser.parse(stat));
    }
}
