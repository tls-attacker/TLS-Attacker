/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

// Fewer test cases here because of overlap with VRFY-553 Reply.
class EXPNReplyParserTest {
    @Test
    void testValidReplies() {
        String[] validCommands = {
                "250 John J. D. Doe <john.doe@mail.com>\r\n",
                "250 <john.doe@mail.com>\r\n",
                "250 john.doe@mail.com\r\n",
                "250-John <john.doe@mail.com>\r\n250-Jane <jane.doe@mail.com>\r\n250 Jin Doe <jin.doe@mail.com>\r\n",
                "252 Cannot VRFY user, but will accept message and attempt delivery to <john@mail.com>\r\n",
                "500  Syntax error, command unrecognized\r\n",
                "550  Requested action not taken: mailbox unavailable\r\n",
                "502 Command not implemented\r\n"
        };

        for (String command : validCommands) {
            EXPNReplyParser parser =
                    new EXPNReplyParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNReply expn = new SmtpEXPNReply();
            assertDoesNotThrow(() -> parser.parse(expn));
            assertEquals(expn.getStatusCode(), command.substring(0, 3));
        }
    }
}
