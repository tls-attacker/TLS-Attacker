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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

class VRFYReplyTest {
    @Test
    void testParseValidReplies() {
        String[] validReplies = {
            "250 John <john@mail.com>\r\n",
            "250 John Doe <john.doe@mail.com>\r\n",
            "250 John J. D. Doe <john.doe@mail.com>\r\n",
            "250 <john.doe@mail.com>\r\n",
            "250 john.doe@mail.com\r\n",
            "251 User not local; will forward to <john@mail.com>\r\n",
            "252 Cannot VRFY user, but will accept message and attempt delivery to <john@mail.com>\r\n",
            "550  Requested action not taken: mailbox unavailable\r\n",
            "551  User not local; please try <john@mail.com>\r\n",
            "553 User ambiguous\r\n",
            "553-User ambiguous\r\n553-John Doe <john.doe@mail.com>\r\n553 Jane Doe <jane.doe@mail.com>\r\n",
            "553-John Doe <john.doe@mail.com>\r\n553-Jane Doe <jane.doe@mail.com>\r\n553 Jin Doe <jin.doe@mail.com>\r\n",
            "553-John Doe <john.doe@mail.com>\r\n553-Jane Doe <jane.doe@mail.com>\r\n553 User ambiguous\r\n",
        };

        for (String reply : validReplies) {
            VRFYReplyParser parser =
                    new VRFYReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertDoesNotThrow(() -> parser.parse(vrfy));
            assertEquals(vrfy.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
        }
    }

    @Test
    void testParseAndSerialize() {
        String reply = "250 john <john@mail.com>\r\n";

        VRFYReplyParser parser =
                new VRFYReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpVRFYReply vrfy = new SmtpVRFYReply();
        assertDoesNotThrow(() -> parser.parse(vrfy));

        assertTrue(vrfy.getFullNames().size() == 1 && vrfy.getMailboxes().size() == 1);
        assertTrue(vrfy.mailboxesAreEnclosed());
        assertEquals(vrfy.getReplyCode(), 250);
        assertEquals(vrfy.getFullNames().get(0), "john");
        assertEquals(vrfy.getMailboxes().get(0), "john@mail.com");

        Serializer serializer = serialize(vrfy);
        assertEquals(reply, serializer.getOutputStream().toString());
    }

    @Test
    void testParseInvalidReplies() {
        String[] invalidReplies = {
            "250 John john@mail.com\r\n",
            "250 John Doe <\"john.doe@mail.com>\r\n",
            "250 <john.doe@mail.com>>\r\n",
            "250 John <john@mail.com>\r\n250 John <john@mail.com>\r\n",
            "250 ",
            "250+ John Doe <john.doe@mail.com>\r\n",
            "251 User not local\r\n", // mailbox must be provided
            "553 User ambiguous\r\n553 User ambiguous\r\n", // two descriptions
            "555\r\n", // invalid code
            "\r\n",
            "250- John Doe <john.doe@mail.com>\r\n",
            "553-John Doe <john.doe@mail.com>\r\n553 Jane Doe <jane.doe@mail.com>\r\n553-Jin Doe <jin.doe@mail.com>\r\n"
        };

        for (String reply : invalidReplies) {
            VRFYReplyParser parser =
                    new VRFYReplyParser(
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertThrows(RuntimeException.class, () -> parser.parse(vrfy));
        }
    }

    @Test
    void testSimpleSerialize() {
        testSerialize(250, null, "John Doe", "<john.doe@gmail.com>", true);
        testSerialize(250, null, null, "<john.doe@gmail.com>", true);
        testSerialize(250, null, null, "john.doe@gmail.com", false);
        testSerialize(502, "Unimplemented command.", null, null, false);
        testSerialize(251, "User not local; will forward to ", null, "<some@email.com>", true);
    }

    @Test
    void testAmbiguousSerialize() {
        String crlf = "\r\n";
        String sp = " ";
        String dash = "-";

        int replyCode = 553;
        String description = "User ambiguous.";
        List<String> fullNames = Arrays.asList("a", "b");
        List<String> mailboxes = Arrays.asList("a@mail.com", "b@mail.com");
        List<String> enclosedMailboxes = Arrays.asList("<a@mail.com>", "<b@mail.com>");

        // case: 553 User ambiguous.
        SmtpVRFYReply vrfy =
                new SmtpVRFYReply(
                        replyCode, description, new LinkedList<>(), new LinkedList<>(), false);
        String expectedResult = replyCode + sp + description + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: 553-User ambiguous + multiple mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, description, new LinkedList<>(), mailboxes, true);
        expectedResult =
                replyCode
                        + dash
                        + description
                        + crlf
                        + replyCode
                        + dash
                        + enclosedMailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + enclosedMailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: 553-User ambiguous + multiple full names & mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, description, fullNames, mailboxes, true);
        expectedResult =
                replyCode
                        + dash
                        + description
                        + crlf
                        + replyCode
                        + dash
                        + fullNames.get(0)
                        + sp
                        + enclosedMailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + fullNames.get(1)
                        + sp
                        + enclosedMailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: multiple mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, null, new LinkedList<>(), mailboxes, true);
        expectedResult =
                replyCode
                        + dash
                        + enclosedMailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + enclosedMailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: multiple full names and mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, null, fullNames, mailboxes, true);
        expectedResult =
                replyCode
                        + dash
                        + fullNames.get(0)
                        + sp
                        + enclosedMailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + fullNames.get(1)
                        + sp
                        + enclosedMailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);
    }

    private void testAmbiguousSerialize(SmtpVRFYReply reply, String expectedResult) {
        Serializer serializer = serialize(reply);
        assertEquals(expectedResult, serializer.getOutputStream().toString());
    }

    private void testSerialize(
            int replyCode,
            String description,
            String fullName,
            String mailbox,
            boolean mailboxesAreEnclosed) {
        SmtpVRFYReply vrfy =
                new SmtpVRFYReply(replyCode, description, fullName, mailbox, mailboxesAreEnclosed);
        String expectedResult = expectedSerializeResult(replyCode, description, fullName, mailbox);

        Serializer serializer = serialize(vrfy);
        assertEquals(expectedResult, serializer.getOutputStream().toString());
    }

    private Serializer serialize(SmtpVRFYReply reply) {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();

        return serializer;
    }

    private String expectedSerializeResult(
            int replyCode, String description, String fullName, String mailbox) {
        StringBuilder sb = new StringBuilder();
        String sp = " ";
        String crlf = "\r\n";

        sb.append(replyCode);
        if (description != null) sb.append(sp).append(description);
        if (fullName != null) sb.append(sp).append(fullName);
        if (mailbox != null) sb.append(sp).append(mailbox);

        sb.append(crlf);

        return sb.toString();
    }
}
