/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.smtp.parser.command.EXPNCommandParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class EXPNCommandTest {
    @Test
    void testParseValidCommands() {
        String[] validCommands = {
            "EXPN john\r\n", "EXPN \"John Doe\"\r\n", "EXPN \"john.doe@gmail.com\"\r\n"
        };

        EXPNCommandParser parser;
        for (String command : validCommands) {
            parser =
                    new EXPNCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNCommand expn = new SmtpEXPNCommand();
            parser.parse(expn);

            assertEquals(expn.getVerb(), "EXPN");
            assertEquals(expn.getParameters(), command.substring(5, command.length() - 2));
        }
    }

    @Test
    void testParseInvalidCommands() {
        String[] invalidCommands = {
            "EXPN John Doe\r\n", "EXPN john john.doe@gmail.com\r\n", "EXPN john.doe@gmail.com\r\n",
        };

        for (String command : invalidCommands) {
            EXPNCommandParser parser =
                    new EXPNCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpEXPNCommand expn = new SmtpEXPNCommand();
            assertDoesNotThrow(() -> parser.parse(expn));
            assertEquals(expn.getVerb(), "EXPN");
            assertEquals(expn.getParameters(), command.substring(5, command.length() - 2));
        }
    }
}
