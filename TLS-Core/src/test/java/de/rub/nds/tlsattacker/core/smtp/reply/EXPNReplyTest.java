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
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.EXPNReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class EXPNReplyTest {

    @Test
    void serializeValid250Reply() {
        SmtpEXPNReply expn = new SmtpEXPNReply();
        expn.setReplyCode(250);
        expn.setReplyLines(List.of("John <john.doe@mail.com>", "Jane Doe <jane.doe@mail.com>"));

        Serializer serializer = serialize(expn);
        assertEquals("250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void parseAndSerializeValid250Reply() {
        String reply = "250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n";

        EXPNReplyParser parser =
                new EXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));

        assertEquals(expn.getReplyCode(), 250);
        assertEquals(expn.getMailboxes().get(0), "john.doe@mail.com");
        assertEquals(expn.getMailboxes().get(1), "jane.doe@mail.com");

        Serializer serializer = serialize(expn);
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "500 Syntax error, command unrecognized\r\n",
            "550 Requested action not taken: mailbox unavailable\r\n",
            "502 Command not implemented\r\n"
    })
    void parseValidDescriptionReplies(String reply) {
        EXPNReplyParser parser =
                new EXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));
        assertEquals(expn.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
        assertEquals(expn.getReplyLines().size(), 1);
        assertEquals(expn.getReplyCode() + " " + expn.getReplyLines().get(0) + "\r\n", reply);
    }

    private Serializer serialize(SmtpEXPNReply reply) {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();

        return serializer;
    }
}
