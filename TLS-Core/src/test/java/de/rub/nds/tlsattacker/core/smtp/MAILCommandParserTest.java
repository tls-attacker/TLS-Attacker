package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class MAILCommandParserTest {
    @Test
    void testParse() {
        String stringMessage = "MAIL seal@upb.de\r\n";

        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("seal@upb.de", mail.getReversePath());
    }
}
