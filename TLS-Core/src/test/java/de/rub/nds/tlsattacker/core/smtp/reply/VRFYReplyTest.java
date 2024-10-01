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
import de.rub.nds.tlsattacker.core.smtp.parser.reply.VRFYReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpVRFYReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class VRFYReplyTest {
    @ParameterizedTest
    @MethodSource("provideValidReplies")
    void testParseValidReplies(String reply, List<String> usernames, List<String> mailboxes) {
        VRFYReplyParser parser =
                new VRFYReplyParser(
                        new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));

        SmtpVRFYReply vrfy = new SmtpVRFYReply();
        assertDoesNotThrow(() -> parser.parse(vrfy));

        assertEquals(vrfy.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));

        for (int i = 0; i < mailboxes.size(); i++) {
            assertEquals(vrfy.getData().get(i).getUsername(), usernames.get(i));
            assertEquals(vrfy.getData().get(i).getMailbox(), mailboxes.get(i));
        }
    }

    static Stream<Arguments> provideValidReplies() {
        return Stream.of(
                Arguments.of(
                        "250 John <john@mail.com>\r\n",
                        List.of("John"),
                        List.of("<john@mail.com>")),
                Arguments.of(
                        "553-John Doe <john.doe@mail.com>\r\n553 Jane Doe <jane.doe@mail.com>\r\n",
                        List.of("John Doe", "Jane Doe"),
                        List.of("<john.doe@mail.com>", "<jane.doe@mail.com>")));
    }

    @Test
    void testSerialize() {
        String replyContent = "John Doe <john.doe@gmail.com>";
        SmtpVRFYReply vrfy = new SmtpVRFYReply();
        vrfy.setReplyCode(250);
        vrfy.addUsernameAndMailbox("John Doe", "<john.doe@gmail.com>");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Serializer<?> serializer = vrfy.getSerializer(context);
        serializer.serialize();
        assertEquals("250 " + replyContent + "\r\n", serializer.getOutputStream().toString());
    }
}
