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

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpVRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpVRFYCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class VRFYCommandTest {
    @Test
    void testParseCommands() {
        String[] validCommands = {
            "VRFY john\r\n", "VRFY \"John Doe\"\r\n", "VRFY \"john.doe@gmail.com\"\r\n"
        };

        SmtpVRFYCommandParser parser;
        for (String command : validCommands) {
            parser =
                    new SmtpVRFYCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));

            SmtpVRFYCommand vrfy = new SmtpVRFYCommand();
            parser.parse(vrfy);

            assertEquals(vrfy.getVerb(), "VRFY");
            assertEquals(vrfy.getParameters(), command.substring(5, command.length() - 2));
        }
    }

    @Test
    void testSerialize() {
        // given an SmtpEHLOCommand see if getSerializer leads to something worthwhile.
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpVRFYCommand vrfy = new SmtpVRFYCommand("\"john@mail.com\"");
        SmtpVRFYCommandPreparator preparator = vrfy.getPreparator(context.getContext());
        Serializer serializer = vrfy.getSerializer(context.getContext());
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals(
                "VRFY \"john@mail.com\"\r\n", serializer.getOutputStream().toString());
    }
}
