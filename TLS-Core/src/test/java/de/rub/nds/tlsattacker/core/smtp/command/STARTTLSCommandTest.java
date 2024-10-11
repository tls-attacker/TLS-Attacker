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
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class STARTTLSCommandTest {
    @Test
    void testParse() {
        String stringMessage = "STARTTLS\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpSTARTTLSCommand starttlsCommand = new SmtpSTARTTLSCommand();
        Parser parser =
                starttlsCommand.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(starttlsCommand);
        assertEquals("STARTTLS", starttlsCommand.getVerb());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpSTARTTLSCommand starttlsCommand = new SmtpSTARTTLSCommand();
        Preparator preparator = starttlsCommand.getPreparator(context);
        Serializer serializer = starttlsCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("STARTTLS\r\n", serializer.getOutputStream().toString());
    }
}
