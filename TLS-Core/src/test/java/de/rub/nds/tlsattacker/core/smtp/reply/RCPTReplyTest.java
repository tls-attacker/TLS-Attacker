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
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Tests for RCPT reply.
 *
 * <p>Includes parsing of valid and invalid syntax and serialization.
 */
class RCPTReplyTest {
    @Test
    public void testSerialize() {
        SmtpRCPTReply reply = new SmtpRCPTReply();
        reply.setReplyCode(250);
        reply.setHumanReadableMessage("OK");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("250 OK\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testParseValidReplies() {
        String[] validReplies = {
            "250 Ok\r\n",
            "251 User not local; will forward to <seal@upb.de>\r\n",
            "450 Requested mail action not taken: mailbox unavailable\r\n",
            "451 Requested action aborted: local error in processing\r\n",
            "452 Requested action not taken: insufficient system storage\r\n",
            "455 Server unable to accommodate parameters\r\n",
            "550 Requested action not taken: mailbox unavailable\r\n",
            "551 User not local; please try <user@example.com>\r\n",
            "552 Requested mail action aborted: exceeded storage allocation\r\n",
            "553 Requested action not taken: mailbox name not allowed\r\n",
            "503 Bad sequence of commands\r\n",
            "555 MAIL FROM/RCPT TO parameters not recognized or not implemented\r\n"
        };

        for (String reply : validReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpRCPTReply RCPT = new SmtpRCPTReply();
            SmtpReplyParser parser =
                    RCPT.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            parser.parse(RCPT);
            //            assertTrue(RCPT.isValidReply());
            assertEquals(Integer.parseInt(reply.substring(0, 3)), RCPT.getReplyCode());
        }
    }

    @Test
    void testParseNegativeReplies() {
        String[] invalidReplies = {"321 No such user here\r\n", "123 Everything fine\r\n"};

        for (String reply : invalidReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpRCPTReply RCPT = new SmtpRCPTReply();
            SmtpReplyParser parser =
                    RCPT.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            parser.parse(RCPT);
            //            assertFalse(RCPT.isValidReply());
        }
    }

    @Test
    void testParseInvalidReplies() {
        String[] invalidReplies = {
            "User not local; will forward to <seal@upb.de>\r\n", "250\r\n",
        };

        for (String reply : invalidReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpRCPTReply RCPT = new SmtpRCPTReply();
            SmtpReplyParser parser =
                    RCPT.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            assertThrows(ParserException.class, () -> parser.parse(RCPT));
        }
    }
}
