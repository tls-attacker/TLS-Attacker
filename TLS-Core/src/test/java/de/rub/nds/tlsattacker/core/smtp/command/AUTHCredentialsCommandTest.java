/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCredentialsParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class AUTHCredentialsCommandTest {
    @Test
    void testParseBasic() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCredentialsCommand authCredentials = new SmtpAUTHCredentialsCommand();
        String stringMessage = "qweqweqwe==\r\n";

        AUTHCredentialsParser parser =
                authCredentials.getParser(
                        context.getContext(),
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(authCredentials);
        assertEquals(authCredentials.getCredentials(), "qweqweqwe==");
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCredentialsCommand cmd = new SmtpAUTHCredentialsCommand("qweqweqwe==");

        Preparator<?> preparator = cmd.getPreparator(context.getContext());
        Serializer<?> serializer = cmd.getSerializer(context.getContext());
        preparator.prepare();
        serializer.serialize();

        assertEquals("qweqweqwe==\r\n", serializer.getOutputStream().toString());
    }
}
