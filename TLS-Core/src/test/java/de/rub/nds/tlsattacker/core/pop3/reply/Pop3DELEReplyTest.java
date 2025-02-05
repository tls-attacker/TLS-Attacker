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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.DELReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pop3DELEReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3DELEReply del = new Pop3DELEReply();
        del.setStatusIndicator("+OK");
        del.setHumanReadableMessage("message 1 deleted");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = del.getSerializer(context);
        serializer.serialize();

        assertEquals("+OK message 1 deleted\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "-ERR message 2 already deleted\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3DELEReply del = new Pop3DELEReply();
        DELReplyParser parser =
                del.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(del);

        assertEquals("-ERR", del.getStatusIndicator());
        assertEquals("message 2 already deleted", del.getHumanReadableMessage());
    }
}
