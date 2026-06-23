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
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3GenericReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class Pop3QUITReplyTest {

    @Test
    public void serializeValidReply() {
        Pop3QUITReply quit = new Pop3QUITReply();
        quit.setStatusIndicator("+OK");
        quit.setHumanReadableMessage("dewey POP3 server signing off");
        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = quit.getSerializer(context.getContext());
        serializer.serialize();

        assertEquals(
                "+OK dewey POP3 server signing off\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testParse() {
        String message = "+OK dewey POP3 server signing off\r\n";

        Pop3Context context = new Pop3Context(new Context(new State(), new OutboundConnection()));
        Pop3QUITReply quit = new Pop3QUITReply();
        Pop3GenericReplyParser<Pop3QUITReply> parser =
                quit.getParser(
                        context.getContext(),
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(quit);

        assertEquals("+OK", quit.getStatusIndicator());
        assertEquals("dewey POP3 server signing off", quit.getHumanReadableMessage());
    }
}
