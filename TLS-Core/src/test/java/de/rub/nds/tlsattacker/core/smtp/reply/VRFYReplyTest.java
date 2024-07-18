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
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class VRFYReplyTest {
    @Test
    void testParseValidReplies() {
        String[] validReplies = {
            "250 John <john@mail.com>\r\n",
            "251 User not local; will forward to <john@mail.com>\r\n",
            "551  User not local; please try <john@mail.com>\r\n",
            "553 User ambiguous\r\n",
            "553-User ambiguous\r\n553-John Doe <john.doe@mail.com>\r\n553 Jane Doe <jane.doe@mail.com>\r\n"
        };

        for (String reply : validReplies) {
            VRFYReplyParser parser =
                    new VRFYReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertDoesNotThrow(() -> parser.parse(vrfy));
            assertEquals(vrfy.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
            assertEquals(vrfy.getMailboxes().size(), getNumberOfMailboxes(reply));
        }
    }

    int getNumberOfMailboxes(String str) {
        return str.length() - str.replace("@", "").length();
    }

    @Test
    void testParseInvalidReplies() {
        String[] invalidReplies = {
            "250 John Doe <\"john.doe@mail.com>\r\n",
            "250 <john.doe@mail.com>>\r\n",
            "250 John <john@mail.com>\r\n250 John <john@mail.com>\r\n",
            "250 \r\n",
            "250+ John Doe <john.doe@mail.com>\r\n",
            "251 User not local\r\n", // mailbox must be provided
            "553 User ambiguous\r\n553 User ambiguous\r\n", // two descriptions
            "250- John Doe <john.doe@mail.com>\r\n",
            "553-John Doe <john.doe@mail.com>\r\n553 Jane Doe <jane.doe@mail.com>\r\n553-Jin Doe <jin.doe@mail.com>\r\n"
        };

        for (String reply : invalidReplies) {
            VRFYReplyParser parser =
                    new VRFYReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertDoesNotThrow(() -> parser.parse(vrfy));
            assertEquals(vrfy.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
            assertEquals(vrfy.getMailboxes().size(), getNumberOfMailboxes(reply));
        }
    }

    @Test
    void testSerialize() {
        String replyContent = "John Doe <john.doe@gmail.com>";
        SmtpVRFYReply vrfy = new SmtpVRFYReply(250, List.of(replyContent));

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = vrfy.getPreparator(context);
        Serializer serializer = vrfy.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250 " + replyContent + "\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testParseAndSerialize() {
        String reply = "250 John Doe <john.doe@gmail.com>\r\n";

        VRFYReplyParser parser =
                new VRFYReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpVRFYReply vrfy = new SmtpVRFYReply();
        parser.parse(vrfy);

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer serializer = vrfy.getSerializer(context);
        serializer.serialize();
        assertEquals(
                "250  John Doe <john.doe@gmail.com>\r\n", serializer.getOutputStream().toString());
    }
}
