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
import org.junit.jupiter.api.Test;

public class EXPNReplyTest {

    @Test
    void serializeValid250Reply() {
        String reply = "250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n";

        SmtpEXPNReply expn =
                new SmtpEXPNReply(
                        250,
                        null,
                        Arrays.asList("John", "Jane Doe"),
                        Arrays.asList("john.doe@mail.com", "jane.doe@mail.com"),
                        true);

        Serializer serializer = serialize(expn);
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @Test
    void parseAndSerializeValid250Reply() {
        String reply = "250-John <john.doe@mail.com>\r\n250 Jane Doe <jane.doe@mail.com>\r\n";

        EXPNReplyParser parser =
                new EXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));

        assertTrue(expn.getFullNames().size() == 2 && expn.getMailboxes().size() == 2);
        assertTrue(expn.mailboxesAreEnclosed());
        assertEquals(expn.getReplyCode(), 250);
        assertEquals(expn.getFullNames().get(0), "John");
        assertEquals(expn.getFullNames().get(1), "Jane Doe");
        assertEquals(expn.getMailboxes().get(0), "john.doe@mail.com");
        assertEquals(expn.getMailboxes().get(1), "jane.doe@mail.com");

        Serializer serializer = serialize(expn);
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @Test
    void parseAndSerializeValidDescriptionAndMailboxReply() {
        String reply =
                "252 Cannot VRFY user, but will accept message and attempt delivery to <john@mail.com>\r\n";

        EXPNReplyParser parser =
                new EXPNReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertDoesNotThrow(() -> parser.parse(expn));
        assertEquals(expn.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
        assertEquals(
                expn.getDescription(),
                "Cannot VRFY user, but will accept message and attempt delivery to");
        assertEquals(expn.getMailboxes().get(0), "john@mail.com");

        Serializer serializer = serialize(expn);
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @Test
    void parseInvalidDescriptionAndMailboxReply() {
        // Invalid status code for EXPN-reply:
        String validReply =
                "251 Cannot VRFY user, but will accept message and attempt delivery to <john@mail.com>\r\n";

        EXPNReplyParser parser =
                new EXPNReplyParser(
                        new ByteArrayInputStream(validReply.getBytes(StandardCharsets.UTF_8)));

        SmtpEXPNReply expn = new SmtpEXPNReply();
        assertThrows(RuntimeException.class, () -> parser.parse(expn));
    }

    @Test
    void parseValidDescriptionReplies() {
        String[] validCommands = {
            "500 Syntax error, command unrecognized\r\n",
            "550 Requested action not taken: mailbox unavailable\r\n",
            "502 Command not implemented\r\n"
        };

        for (String command : validCommands) {
            EXPNReplyParser parser =
                    new EXPNReplyParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNReply expn = new SmtpEXPNReply();
            assertDoesNotThrow(() -> parser.parse(expn));
            assertEquals(expn.getReplyCode(), Integer.parseInt(command.substring(0, 3)));
            assertEquals(expn.getDescription(), command.substring(4, command.length() - 2));
        }
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
