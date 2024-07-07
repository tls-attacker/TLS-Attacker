package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpVRFYReply;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class VRFYReplyParserTest {
    @Test
    void testValidReplies() {
        String[] validCommands = {
                "250 John <john@mail.com>\r\n",
                "250 John Doe <john.doe@mail.com>\r\n",
                "250 John J. D. Doe <john.doe@mail.com>\r\n",
                "250 <john.doe@mail.com>\r\n",
                "250 john.doe@mail.com\r\n",
                "250- John Doe <john.doe@mail.com>\r\n",
                "251 User not local; will forward to <john@mail.com>\r\n",
                "252 Cannot VRFY user, but will accept message and attempt delivery to <john@mail.com>\r\n",

                "550  Requested action not taken: mailbox unavailable\r\n",
                "551  User not local; please try <john@mail.com>\r\n",
                "553 User ambiguous\r\n",
                "553 User ambiguous\r\n553-John Doe <john.doe@mail.com>\r\n553-Jane Doe <jane.doe@mail.com>\r\n",
                "553-John Doe <john.doe@mail.com>\r\n553-Jane Doe <jane.doe@mail.com>\r\n553-Jin Doe <jin.doe@mail.com>\r\n",
                "553-John Doe <john.doe@mail.com>\r\n553-Jane Doe <jane.doe@mail.com>\r\n553 User ambiguous\r\n",
        };

        for (String command : validCommands) {
            VRFYReplyParser parser = new VRFYReplyParser(
                    new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertDoesNotThrow(() -> parser.parse(vrfy));
            assertEquals(vrfy.getStatusCode(), command.substring(0, 3));
        }
    }

    @Test
    void testInvalidReplies() {
        String[] invalidCommands = {
                "250 John john@mail.com\r\n",
                "250 John Doe <\"john.doe@mail.com>\r\n",
                "250 <john.doe@mail.com>>\r\n",
                "250 John <john@mail.com>\r\n250 John <john@mail.com>\r\n",
                "250 ",
                "250+ John Doe <john.doe@mail.com>\r\n",
                "251 User not local\r\n", // mailbox must be provided

                "553 User ambiguous\r\n553 User ambiguous\r\n", // two descriptions
                "555", // invalid code
                ""
        };

        for (String command : invalidCommands) {
            VRFYReplyParser parser = new VRFYReplyParser(
                    new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYReply vrfy = new SmtpVRFYReply();
            assertThrows(RuntimeException.class, () -> parser.parse(vrfy));
        }
    }
}
