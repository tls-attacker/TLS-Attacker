/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3GenericReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

public class Pop3ReplyParserTest {

    @Test
    void readSingleLineReply() {
        String input = "+OK OK\r\n";
        Pop3ReplyParser<?> parser =
                new Pop3GenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));

        List<String> lines = parser.readWholeReply();
        assertEquals(1, lines.size());
        String firstLine = lines.get(0);
        assertEquals(firstLine, "+OK OK");
    }

    @Test
    void readMultiLineReply() {
        String input = "-ERR bad\r\nverybad\r\n.\r\n";
        Pop3ReplyParser<?> parser =
                new Pop3GenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        List<String> lines = parser.readWholeReply();
        assertEquals(3, lines.size());
        assertLinesMatch(List.of("-ERR bad", "verybad", "."), lines);
    }

    @Test
    void readInvalidMultiLineReply() {
        String input = "-ERR bad\r\n.verybad\r\n";
        Pop3ReplyParser<?> parser =
                new Pop3GenericReplyParser<>(
                        new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)));
        assertThrows(EndOfStreamException.class, parser::readWholeReply);
    }
}
