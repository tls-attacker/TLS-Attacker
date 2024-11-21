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

class USERReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3USERReply user = new Pop3USERReply();
        user.setStatusIndicator("+OK");
        user.setUser("JuanFernandez");
        user.setHumanReadableMessage("is a real hoopy frood");

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = user.getSerializer(context);
        serializer.serialize();

        assertEquals(
                "+OK JuanFernandez is a real hoopy frood\r\n",
                serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK JuanFernandez is a real hoopy frood\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3USERReply user = new Pop3USERReply();
        USERReplyParser parser =
                user.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(user);

        assertEquals("+OK", user.getStatusIndicator());
        assertEquals("JuanFernandez", user.getUser());
        assertEquals("is a real hoopy frood", user.getHumanReadableMessage());
    }

    @Test
    public void parseERRReply() {
        String reply = "-ERR JuanFernandez mailbox does not exist\r\n";
        Pop3USERReply user = new Pop3USERReply();
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));

        USERReplyParser parser =
                user.getParser(
                        context, new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
        parser.parse(user);

        assertEquals(user.getStatusIndicator(), "-ERR");
        assertEquals(user.getUser(), "JuanFernandez");
        assertEquals(user.getHumanReadableMessage(), "mailbox does not exist");
    }
}
