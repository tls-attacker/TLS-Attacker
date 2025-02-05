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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.RETRReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class RETRReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3RETRReply ret = new Pop3RETRReply();
        ret.setStatusIndicator("+OK");
        ret.setHumanReadableMessage("113 octets");
        ret.addMessagePart("Hello Juan Fernandez I hope this email finds you well.");
        ret.addMessagePart("Did you hear about SEAL, a super cool project group of UPB.");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = ret.getSerializer(context);
        serializer.serialize();

        assertEquals(
                "+OK 113 octets\r\nHello Juan Fernandez I hope this email finds you well."
                        + "\r\nDid you hear about SEAL, a super cool project group of UPB.\r\n.\r\n",
                serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message =
                "+OK 113 octets\r\nHello Juan Fernandez I hope this email finds you well."
                        + "\r\nDid you hear about SEAL, a super cool project group of UPB.\r\n.\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3RETRReply ret = new Pop3RETRReply();
        RETRReplyParser parser =
                ret.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ret);

        List<String> savedMessage = new ArrayList<>();
        savedMessage.add("Hello Juan Fernandez I hope this email finds you well.");
        savedMessage.add("Did you hear about SEAL, a super cool project group of UPB.");

        assertEquals("+OK", ret.getStatusIndicator());
        assertEquals("113 octets", ret.getHumanReadableMessage());
        assertEquals(savedMessage, ret.getMessage());
    }

    @Test
    public void parseERRReply() {
        String reply = "-ERR no Info\r\n";
        Pop3RETRReply ret = new Pop3RETRReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        RETRReplyParser parser =
                ret.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> parser.parse(ret));
        assertEquals(ret.getStatusIndicator(), "-ERR");
        assertEquals(ret.getHumanReadableMessage(), "no Info");
    }
}
