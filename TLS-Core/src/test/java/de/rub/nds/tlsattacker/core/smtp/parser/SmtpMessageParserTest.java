package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SmtpMessageParserTest {

    private static class FakeSmtpMessageParser extends SmtpMessageParser<SmtpMessage> {
        public FakeSmtpMessageParser(InputStream stream) {super(stream);}
        @Override
        public void parse(SmtpMessage o) {}
    }
    @Test
    void testValidSingleLine() {
        String stringMessage = "EHLO test\r\n";
        SmtpMessageParser<SmtpMessage> parser = new FakeSmtpMessageParser(new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        String singleLine = parser.parseSingleLine();
        assertEquals("EHLO test", singleLine);
    }
    @Test
    void testValidSingleLineWithParseAll() {
        String stringMessage = "EHLO test\r\n";
        SmtpMessageParser<SmtpMessage> parser = new FakeSmtpMessageParser(new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        List<String> singleLine = parser.parseAllLines();
        assertLinesMatch(List.of("EHLO test"), singleLine);
    }

    @Test
    void testInvalidSingleLine() {
        String stringMessage = "EHLO test\ra";
        SmtpMessageParser<SmtpMessage> parser = new FakeSmtpMessageParser(new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        assertThrows(EndOfStreamException.class, parser::parseSingleLine);
    }

    @Test
    void testValidMultiLine() {
        String stringMessage = "EHLO test\r\n250-Hello\r\n250-World\r\n250 END\r\n";
        SmtpMessageParser<SmtpMessage> parser = new FakeSmtpMessageParser(new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        List<String> multiLine = parser.parseAllLines();
        assertLinesMatch(List.of("EHLO test", "250-Hello", "250-World", "250 END"), multiLine);
    }
}