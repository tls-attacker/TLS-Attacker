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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.LISTReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class LISTReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3LISTReply list = new Pop3LISTReply();
        list.setStatusIndicator("+OK");
        List<String> messageNumbers = Arrays.asList("1", "2");
        List<String> octetNumbers = Arrays.asList("350", "120");
        list.setMessageNumbers(messageNumbers);
        list.setMessageOctets(octetNumbers);
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = list.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK\r\n1 350\r\n2 120\r\n.\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK displaying messages\r\n1 120\r\n2 350\r\n.\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTReply list = new Pop3LISTReply();
        LISTReplyParser parser =
                list.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(list);
        List<String> messageNumbers = Arrays.asList("1", "2");
        List<String> octetNumbers = Arrays.asList("120", "350");

        assertEquals("+OK", list.getStatusIndicator());
        assertEquals(messageNumbers, list.getMessageNumbers());
        assertEquals(octetNumbers, list.getMessageOctets());
    }

    @Test
    public void parseInvalidReply() {
        String reply = "-ERR no Info\r\n";
        Pop3LISTReply list = new Pop3LISTReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        LISTReplyParser parser =
                list.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(list));
        assertEquals(list.getStatusIndicator(), "-ERR");
        assertEquals(list.getHumanReadableMessage(), "no Info");
    }

    @Test
    public void parseOKReply() {
        String reply = "+OK no Info\r\n";
        Pop3LISTReply list = new Pop3LISTReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        LISTReplyParser parser =
                list.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(list));
        assertEquals(list.getStatusIndicator(), "+OK");
        assertEquals(list.getHumanReadableMessage(), "no Info");
    }
}
