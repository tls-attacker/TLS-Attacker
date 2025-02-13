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
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpAUTHCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class AUTHCommandTest {

    @Test
    void testParseBasic() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand();
        String stringMessage = "AUTH PLAIN qweqweqwe==\r\n";

        SmtpAUTHCommandParser parser =
                auth.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(auth);
        assertEquals("AUTH", auth.getVerb());
        assertEquals("PLAIN", auth.getSaslMechanism());
        assertEquals("qweqweqwe==", auth.getInitialResponse());
    }

    @Test
    void testParseInvalid() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand();
        String stringMessage = "AUTH\r\n";

        SmtpAUTHCommandParser parser =
                auth.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        assertThrows(ParserException.class, () -> parser.parse(auth));
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpAUTHCommand auth = new SmtpAUTHCommand("PLAIN", "qweqweqwe==");

        Preparator<?> preparator = auth.getPreparator(context);
        Serializer<?> serializer = auth.getSerializer(context);
        preparator.prepare();
        serializer.serialize();

        assertEquals("AUTH PLAIN qweqweqwe==\r\n", serializer.getOutputStream().toString());
    }
}
