package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class VRFYCommandParserTest {
    @Test
    void testValidCommands() {
        String[] validCommands = {
                "VRFY john\r\n",
                "VRFY \"John Doe\"\r\n",
                "VRFY \"john.doe@gmail.com\"\r\n"
        };

        VRFYCommandParser parser;
        for (String command : validCommands) {
            parser = new VRFYCommandParser(
                    new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYCommand vrfy = new SmtpVRFYCommand();
            parser.parse(vrfy);

            assertEquals(vrfy.getVerb(), "VRFY");
            assertEquals(vrfy.getParameters(), command.substring(5, command.length()-2));
        }
    }

    @Test
    void testInvalidCommands() {
        String[] invalidCommands = {
                "VRFY John Doe\r\n",
                "VRFY john john.doe@gmail.com\r\n",
                "VRFY john.doe@gmail.com\r\n",
        };

        for (String command : invalidCommands) {
            VRFYCommandParser parser = new VRFYCommandParser(
                    new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYCommand vrfy = new SmtpVRFYCommand();
            assertThrows(ParserException.class, () -> parser.parse(vrfy));
        }
    }
}
