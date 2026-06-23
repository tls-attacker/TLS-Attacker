/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpEXPNReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class EXPNReplyTest {

    @Test
    void serializeValidReply() {
        SmtpEXPNReply expn = new SmtpEXPNReply();
        expn.setReplyCode(250);
        expn.addUsernameAndMailbox("John", "<john.doe@mail.com>");
        expn.addUsernameAndMailbox("Jane Doe", "<jane.doe@mail.com>");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = expn.getSerializer(context.getContext());
        serializer.serialize();

        assertEquals(
                "250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n",
                serializer.getOutputStream().toString());
    }

    @Test
    void parseAndSerializeValidReply() {
        String reply = "250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n";

        SmtpEXPNReplyParser parser =
                new SmtpEXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));

        assertEquals(expn.getReplyCode(), 250);
        assertEquals(expn.getData().get(0).getUsername(), "John");
        assertEquals(expn.getData().get(0).getMailbox(), "<john.doe@mail.com>");
        assertEquals(expn.getData().get(1).getUsername(), "Jane Doe");
        assertEquals(expn.getData().get(1).getMailbox(), "<jane.doe@mail.com>");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = expn.getSerializer(context.getContext());
        serializer.serialize();
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @Test
    void parseValidDescriptionReply() {
        String reply = "500 Syntax error, command unrecognized\r\n";
        SmtpEXPNReplyParser parser =
                new SmtpEXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));
        assertEquals(expn.getReplyCode(), 500);
        assertEquals(expn.getHumanReadableMessage(), "Syntax error, command unrecognized");
    }
}
