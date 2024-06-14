/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class EHLOParserTest {
    @Test
    void testParse() {
        String stringMessage = "EHLO seal.cs.upb.de\r\n";

        EHLOParser parser =
                new EHLOParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
    }

    @Test
    void testParseAddressLiteral() {
        String stringMessage = "EHLO 127.0.0.1\r\n";

        EHLOParser parser =
                new EHLOParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("127.0.0.1", ehlo.getDomain());
        assertTrue(ehlo.hasAddressLiteral());
    }

    @Test
    void testParseWithoutDomain() {
        String stringMessage = "EHLO  \r\n";

        EHLOParser parser =
                new EHLOParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        assertThrows(ParserException.class, () -> parser.parse(ehlo));
    }
}
