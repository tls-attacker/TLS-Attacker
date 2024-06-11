package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpRequestParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SmtpCommandParserTest {
    @Test
    void testParse() {
        String stringMessage = "EHLO\r\n";

        SmtpCommandParser parser =
                new SmtpCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpCommand ehlo = new SmtpCommand();
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals(null, ehlo.getParameters());
    }
    @Test
    void testParseWithParam() {
        String stringMessage = "EHLO www.rub.de\r\n";

        SmtpCommandParser parser =
                new SmtpCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpCommand ehlo = new SmtpCommand();
        parser.parse(ehlo);
        assertEquals(ehlo.getVerb(), "EHLO");
        assertEquals(ehlo.getParameters(), "www.rub.de");
    }

    @Test
    void invalidCommand() {
        String stringMessage = "EHLO www.rub.de\n";

        SmtpCommandParser parser =
                new SmtpCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpCommand ehlo = new SmtpCommand();
        assertThrows(ParserException.class, () -> parser.parse(ehlo));
    }

}