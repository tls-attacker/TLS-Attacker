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
        testSerialize(250, null, "John Doe", "<john.doe@gmail.com>");
        testSerialize(250, null, null, "<john.doe@gmail.com>");
        testSerialize(250, null, null, "john.doe@gmail.com");
        testSerialize(502, "Unimplemented command.", null, null);
        testSerialize(251, "User not local; will forward to ", null, "<some@email.com>");
    }

    @Test
    void testAmbiguousSerialize() {
        String crlf = "\r\n";
        String sp = " ";
        String dash = "-";

        int replyCode = 553;
        String description = "User ambiguous.";
        List<String> fullNames = Arrays.asList("a", "b");
        List<String> mailboxes = Arrays.asList("<a@mail.com>", "<b@mail.com>");

        // case: 553 User ambiguous.
        SmtpVRFYReply vrfy =
                new SmtpVRFYReply(replyCode, description, new LinkedList<>(), new LinkedList<>());
        String expectedResult = replyCode + sp + description + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: 553-User ambiguous + multiple mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, description, new LinkedList<>(), mailboxes);
        expectedResult =
                replyCode
                        + dash
                        + description
                        + crlf
                        + replyCode
                        + dash
                        + mailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + mailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: 553-User ambiguous + multiple full names & mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, description, fullNames, mailboxes);
        expectedResult =
                replyCode
                        + dash
                        + description
                        + crlf
                        + replyCode
                        + dash
                        + fullNames.get(0)
                        + sp
                        + mailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + fullNames.get(1)
                        + sp
                        + mailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: multiple mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, null, new LinkedList<>(), mailboxes);
        expectedResult =
                replyCode
                        + dash
                        + mailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + mailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);

        // case: multiple full names and mailboxes...
        vrfy = new SmtpVRFYReply(replyCode, null, fullNames, mailboxes);
        expectedResult =
                replyCode
                        + dash
                        + fullNames.get(0)
                        + sp
                        + mailboxes.get(0)
                        + crlf
                        + replyCode
                        + sp
                        + fullNames.get(1)
                        + sp
                        + mailboxes.get(1)
                        + crlf;
        testAmbiguousSerialize(vrfy, expectedResult);
    }

    private void testAmbiguousSerialize(SmtpVRFYReply reply, String expectedResult) {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals(expectedResult, serializer.getOutputStream().toString());
    }

    private void testSerialize(int replyCode, String description, String fullName, String mailbox) {
        SmtpVRFYReply vrfy = new SmtpVRFYReply(replyCode, description, fullName, mailbox);
        String expectedResult = expectedSerializeResult(replyCode, description, fullName, mailbox);

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = vrfy.getPreparator(context);
        Serializer serializer = vrfy.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals(expectedResult, serializer.getOutputStream().toString());
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
