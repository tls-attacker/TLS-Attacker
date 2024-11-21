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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.PASSReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class PASSReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3PASSReply pass = new Pop3PASSReply();
        pass.setStatusIndicator("+OK");
        pass.setHumanReadableMessage("you have 2 messages");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = pass.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK you have 2 messages\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK you have 2 messages\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3PASSReply pass = new Pop3PASSReply();
        PASSReplyParser parser =
                pass.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(pass);

        assertEquals("+OK", pass.getStatusIndicator());
        assertEquals("you have 2 messages", pass.getHumanReadableMessage());
    }
}
