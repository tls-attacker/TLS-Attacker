/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

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
        assertThrows(ParserException.class, parser::parseSingleLine);
    }
}
