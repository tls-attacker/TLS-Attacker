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
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class NOOPCommandTest {

    @Test
    void testParse() {
        String stringMessage = "NOOP\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpNOOPCommand noop = new SmtpNOOPCommand();
        Parser parser =
                noop.getParser(
                        context.getContext(),
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(noop);
        assertEquals("NOOP", noop.getVerb());
    }

    @Test
    void testParseWithParameters() {
        // The NOOP parameters do not do anything, but they are still allowed
        String stringMessage = "NOOP parameter\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpNOOPCommand noop = new SmtpNOOPCommand();
        Parser parser =
                noop.getParser(
                        context.getContext(),
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(noop);
        assertEquals("NOOP", noop.getVerb());
        assertEquals("parameter", noop.getParameters());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpNOOPCommand noopCommand = new SmtpNOOPCommand();
        Preparator preparator = noopCommand.getPreparator(context.getContext());
        Serializer serializer = noopCommand.getSerializer(context.getContext());
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("NOOP\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testHandle() {
        // not expecting anything, just no crashes
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpNOOPCommand noopCommand = new SmtpNOOPCommand();
        Handler handler = noopCommand.getHandler(context.getContext());
        handler.adjustContext(noopCommand);
    }
}
