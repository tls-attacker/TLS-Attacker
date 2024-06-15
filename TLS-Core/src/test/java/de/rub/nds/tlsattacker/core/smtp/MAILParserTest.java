package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class MAILParserTest {
    @Test
    void testParse() {
        String stringMessage = "MAIL seal@upb.de\r\n";

        MAILParser parser =
                new MAILParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("seal@upb.de", mail.getReversePath());
    }
}
