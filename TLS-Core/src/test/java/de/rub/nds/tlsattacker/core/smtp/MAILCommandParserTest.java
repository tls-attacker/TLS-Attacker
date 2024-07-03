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

import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class MAILCommandParserTest {
    @Test
    public void testStandardInput() {
        String stringMessage = "MAIL <seal@upb.de>\r\n";

        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testQuotedStringInput() {
        String stringMessage = "MAIL <\"seal\"@upb.de>\r\n";
        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testSpecialQuotedStringInput() {
        String stringMessage = "MAIL <\"seal@heal\"@upb.de>\r\n";
        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@heal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testInvalidInput() {
        String stringMessage = "MAIL <seal@heal@upb.de>\r\n";
        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        assertThrows(IllegalArgumentException.class, () -> parser.parse(mail));
    }

    @Test
    public void testInvalidPathInput() {
        String stringMessage = "MAIL seal@upb.de\r\n";
        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        assertThrows(IllegalArgumentException.class, () -> parser.parse(mail));
    }
}
