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

class Pop3LISTReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3LISTReply listReply = new Pop3LISTReply();
        listReply.setStatusIndicator("+OK");
        List<Integer> messageNumbers = Arrays.asList(1, 2);
        List<Integer> octetNumbers = Arrays.asList(350, 120);
        listReply.setMessageNumbers(messageNumbers);
        listReply.setMessageSizes(octetNumbers);
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = listReply.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK\r\n1 350\r\n2 120\r\n.\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK displaying messages\r\n1 120\r\n2 350\r\n.\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3LISTReply listReply = new Pop3LISTReply();
        LISTReplyParser parser =
                listReply.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(listReply);
        List<Integer> messageNumbers = Arrays.asList(1, 2);
        List<Integer> octetNumbers = Arrays.asList(120, 350);

        assertEquals("+OK", listReply.getStatusIndicator());
        assertEquals(messageNumbers, listReply.getMessageNumbers());
        assertEquals(octetNumbers, listReply.getMessageSizes());
    }

    @Test
    public void parseInvalidReply() {
        String reply = "-ERR no Info\r\n";
        Pop3LISTReply listReply = new Pop3LISTReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        LISTReplyParser parser =
                listReply.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(listReply));
        assertEquals(listReply.getStatusIndicator(), "-ERR");
        assertEquals(listReply.getHumanReadableMessage(), "no Info");
    }

    @Test
    public void parseOKReply() {
        String reply = "+OK no Info\r\n";
        Pop3LISTReply listReply = new Pop3LISTReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        LISTReplyParser parser =
                listReply.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(listReply));
        assertEquals(listReply.getStatusIndicator(), "+OK");
        assertEquals(listReply.getHumanReadableMessage(), "no Info");
    }

    @Test
    public void testSerializeTwoLineReply() {
        Pop3LISTReply listReply = new Pop3LISTReply();
        listReply.setStatusIndicator("+OK");
        listReply.setHumanReadableMessage("Providing message info.");
        listReply.setMessageNumbers(List.of(1));
        listReply.setMessageSizes(List.of(128));

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = listReply.getSerializer(context);
        serializer.serialize();

        assertEquals(
                "+OK Providing message info.\r\n1 128\r\n.\r\n",
                serializer.getOutputStream().toString());
    }
}
