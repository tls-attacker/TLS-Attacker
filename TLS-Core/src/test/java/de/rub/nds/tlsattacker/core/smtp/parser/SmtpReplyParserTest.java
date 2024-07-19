package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.*;

public class SmtpReplyParserTest {

    @ParameterizedTest
    @ValueSource(strings = { "404 blabla", "111 ASDSADAS ASDSAD ASDASD", "000 k", "250 OK" })
    void isValidReplyEnd(String input) {
        SmtpReplyParser<?> parser = new SmtpReplyParser<>(InputStream.nullInputStream());
        assert parser.isEndOfReply(input);
    }
    @ParameterizedTest
    @ValueSource(strings = { "404blabla", "111-", "666" })
    void isInvalidReplyEnd(String input) {
        SmtpReplyParser<?> parser = new SmtpReplyParser<>(InputStream.nullInputStream());
        assertFalse(parser.isEndOfReply(input));
    }

    @Test
    void readSingleLineReply() {
        String input = "250 OK\r\n250 OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpReplyParser<SmtpReply>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        List<String> lines = parser.readWholeReply();
        assertEquals(1, lines.size());
        String firstLine = lines.get(0);
        assertEquals(firstLine, "250 OK");
    }

    @Test
    void readMultilineReply() {
        String input = "250-OK\r\n250 OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpReplyParser<SmtpReply>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        List<String> lines = parser.readWholeReply();
        assertEquals(2, lines.size());
        assertLinesMatch(List.of("250-OK", "250 OK"), lines);
    }
    @Test
    void readInvalidMultilineReply() {
        String input = "250-OK\r\n250-OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpReplyParser<SmtpReply>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        assertThrows(EndOfStreamException.class, parser::readWholeReply);
    }
}
