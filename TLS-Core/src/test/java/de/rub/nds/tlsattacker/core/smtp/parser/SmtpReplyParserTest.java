/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class SmtpReplyParserTest {

    @ParameterizedTest
    @ValueSource(strings = {"404 blabla", "111 ASDSADAS ASDSAD ASDASD", "000 k", "250 OK"})
    void isValidReplyEnd(String input) {
        SmtpReplyParser<?> parser = new SmtpGenericReplyParser<>(InputStream.nullInputStream());
        assertTrue(parser.isEndOfReply(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"404blabla", "111-", "666"})
    void isInvalidReplyEnd(String input) {
        SmtpReplyParser<?> parser = new SmtpGenericReplyParser<>(InputStream.nullInputStream());
        assertFalse(parser.isEndOfReply(input));
    }

    @Test
    void readSingleLineReply() {
        String input = "250 OK\r\n250 OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));

        List<String> lines = parser.readWholeReply();
        assertEquals(1, lines.size());
        String firstLine = lines.get(0);
        assertEquals("250 OK", firstLine);
    }

    @Test
    void readMultilineReply() {
        String input = "250-OK\r\n250 OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        List<String> lines = parser.readWholeReply();
        assertEquals(2, lines.size());
        assertLinesMatch(List.of("250-OK", "250 OK"), lines);
    }

    @Test
    void readInvalidMultilineReply() {
        String input = "250-OK\r\n250-OK\r\n";
        SmtpReplyParser<?> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        assertThrows(EndOfStreamException.class, parser::readWholeReply);
    }
}
