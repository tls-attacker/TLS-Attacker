/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELPCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.HELPCommandParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HELPCommandParserTest {
    @Test
    void testParseWithoutArguments() {
        String stringMessage = "HELP\r\n";

        HELPCommandParser parser =
                new HELPCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpHELPCommand HELP = new SmtpHELPCommand();
        parser.parse(HELP);
    }

    @Test
    void testParseEHLO() {
        String stringMessage = "HELP EHLO\r\n";

        HELPCommandParser parser =
                new HELPCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpHELPCommand HELP = new SmtpHELPCommand();
        parser.parse(HELP);
        assertEquals("HELP", HELP.getVerb());
        assertEquals("127.0.0.1", HELP.getDomain());
        assertTrue(HELP.hasAddressLiteral());
    }

    @Test
    void testParseRCPT() {
        String stringMessage = "HELP RCPT\r\n";

        HELPCommandParser parser =
                new HELPCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpHELPCommand HELP = new SmtpHELPCommand();
        assertThrows(ParserException.class, () -> parser.parse(HELP));
    }
}
