package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.parser.EXPNCommandParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EXPNCommandTest {
    @Test
    void testParseValidCommands() {
        String[] validCommands = {
                "EXPN john\r\n", "EXPN \"John Doe\"\r\n", "EXPN \"john.doe@gmail.com\"\r\n"
        };

        EXPNCommandParser parser;
        for (String command : validCommands) {
            parser =
                    new EXPNCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNCommand expn = new SmtpEXPNCommand();
            parser.parse(expn);

            assertEquals(expn.getVerb(), "EXPN");
            assertEquals(expn.getParameters(), command.substring(5, command.length() - 2));
        }
    }

    @Test
    void testParseInvalidCommands() {
        String[] invalidCommands = {
                "EXPN John Doe\r\n", "EXPN john john.doe@gmail.com\r\n", "EXPN john.doe@gmail.com\r\n",
        };

        for (String command : invalidCommands) {
            EXPNCommandParser parser =
                    new EXPNCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNCommand expn = new SmtpEXPNCommand();
            assertThrows(ParserException.class, () -> parser.parse(expn));
        }
    }
}
