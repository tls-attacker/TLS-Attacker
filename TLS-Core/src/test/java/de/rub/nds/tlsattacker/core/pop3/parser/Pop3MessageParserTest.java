package de.rub.nds.tlsattacker.core.pop3.parser;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Pop3MessageParserTest {

    private static class FakePop3MessageParser extends Pop3MessageParser<Pop3Message> {
        public FakePop3MessageParser(InputStream stream) {
            super(stream);
        }

        @Override
        public void parse(Pop3Message o) {}
    }

    @Test
    void testValidSingleLine() {
        String stringMessage = "RETR 1\r\n";
        Pop3MessageParser<Pop3Message> parser =
                new Pop3MessageParserTest.FakePop3MessageParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        String singleLine = parser.parseSingleLine();
        assertEquals("RETR 1", singleLine);
    }

    @Test
    void testInvalidSingleLine() {
        String stringMessage = "RETR 1\ra";
        Pop3MessageParser<Pop3Message> parser =
                new Pop3MessageParserTest.FakePop3MessageParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        assertThrows(EndOfStreamException.class, parser::parseSingleLine);
    }
}
