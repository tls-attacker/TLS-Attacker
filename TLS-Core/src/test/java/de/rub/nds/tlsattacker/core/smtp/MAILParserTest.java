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
import de.rub.nds.tlsattacker.core.smtp.parser.MAILParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class MAILParserTest {
    @Test
    void testParse() {
        String stringMessage = "MAIL seal@upb.de\r\n";

        MAILParser parser =
                new MAILParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("seal@upb.de", mail.getReversePath());
    }
}
