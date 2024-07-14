package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.smtp.parser.EXPNReplyParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

// Fewer test cases here because of overlap with VRFY-553 Reply:
public class EXPNReplyTest {
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
            assertEquals(expn.getReplyCode(), Integer.parseInt(command.substring(0, 3)));
        }
    }

}
