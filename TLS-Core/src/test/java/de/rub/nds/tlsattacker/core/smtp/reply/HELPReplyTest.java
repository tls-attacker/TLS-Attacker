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
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpHELPReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Tests for HELP reply.
 *
 * <p>Includes parsing of valid and invalid syntax, serialization, and handler.
 */
class HELPReplyTest {
    @Test
    public void testSerialize() {
        SmtpHELPReply reply = new SmtpHELPReply();
        reply.setReplyCode(214);
        reply.setHumanReadableMessage("Commands: HELO EHLO MAIL RCPT DATA VRFY NOOP QUIT HELP");

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        Preparator preparator = reply.getPreparator(context);
        Serializer serializer = reply.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals(
                "214 Commands: HELO EHLO MAIL RCPT DATA VRFY NOOP QUIT HELP\r\n",
                serializer.getOutputStream().toString());
    }

    @Test
    void testParseValidReplies() {
        String[] validReplies = {
            "211 Commands: HELO EHLO MAIL RCPT DATA VRFY NOOP QUIT HELP\r\n",
            "214 HELO <hostname>: Introduce yourself to the SMTP server\r\n",
            "214 EHLO <hostname>: Extended HELLO command with support for additional features\r\n",
            "214 MAIL FROM:<address>: Specify the sender's email address\r\n",
            "214 RCPT TO:<address>: Specify a recipient's email address\r\n",
            "214 DATA: Start the input of the message content; end with a single dot (.) on a line by itself\r\n",
            "214 VRFY <address>: Verify if the specified email address exists\r\n",
            "214 NOOP: No operation (server responds with OK)\r\n",
            "214 QUIT: Terminate the session\r\n",
            "214 HELP: Show information about the command\r\n",
            "502 TURN Command not implemented\r\n",
            "504 AUTH PLAIN mechanism not supported\r\n"
        };

        for (String reply : validReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpHELPReply helpReply = new SmtpHELPReply();
            SmtpReplyParser parser =
                    helpReply.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            parser.parse(helpReply);
            assertEquals(helpReply.getReplyCode(), Integer.parseInt(reply.substring(0, 3)));
        }
    }

    @Test
    void testParseValidMultiline() {
        String stringMessage =
                "214-Commands supported:\r\n"
                        + "214-HELO EHLO MAIL RCPT\r\n"
                        + "214-DATA RSET VRFY NOOP\r\n"
                        + "214-QUIT HELP EXPN TURN\r\n"
                        + "214-AUTH\r\n"
                        + "214 End of HELP info\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPReply helpReply = new SmtpHELPReply();
        SmtpReplyParser parser =
                helpReply.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(helpReply);

        assertEquals(214, helpReply.getReplyCode());
    }

    @Test
    void testParseInvalidReplyCode() {
        String[] invalidReplies = {"321 No such user here\r\n", "123 Everything fine\r\n"};

        for (String reply : invalidReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpHELPReply helpReply = new SmtpHELPReply();
            SmtpReplyParser parser =
                    helpReply.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            parser.parse(helpReply);
        }
    }

    @Test
    void testParseInvalidSyntax() {
        String[] invalidReplies = {
            "User not local; will forward to <seal@upb.de>\r\n", "250\r\n",
        };

        for (String reply : invalidReplies) {
            SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
            SmtpHELPReply helpReply = new SmtpHELPReply();
            SmtpReplyParser parser =
                    helpReply.getParser(
                            context,
                            new ByteArrayInputStream(reply.getBytes(StandardCharsets.UTF_8)));
            assertThrows(ParserException.class, () -> parser.parse(helpReply));
        }
    }
}
