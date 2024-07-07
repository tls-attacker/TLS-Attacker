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

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class VRFYCommandParserTest {
    @Test
    void testValidCommands() {
        String[] validCommands = {
            "VRFY john\r\n", "VRFY \"John Doe\"\r\n", "VRFY \"john.doe@gmail.com\"\r\n"
        };

        VRFYCommandParser parser;
        for (String command : validCommands) {
            parser =
                    new VRFYCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYCommand vrfy = new SmtpVRFYCommand();
            parser.parse(vrfy);

            assertEquals(vrfy.getVerb(), "VRFY");
            assertEquals(vrfy.getParameters(), command.substring(5, command.length() - 2));
        }
    }

    @Test
    void testInvalidCommands() {
        String[] invalidCommands = {
            "VRFY John Doe\r\n", "VRFY john john.doe@gmail.com\r\n", "VRFY john.doe@gmail.com\r\n",
        };

        for (String command : invalidCommands) {
            VRFYCommandParser parser =
                    new VRFYCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYCommand vrfy = new SmtpVRFYCommand();
            assertThrows(ParserException.class, () -> parser.parse(vrfy));
        }
    }
}
