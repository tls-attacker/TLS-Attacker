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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Tests for HELP command.
 *
 * <p>Includes parsing of valid and invalid syntax, serialization, and handler.
 */
public class HELPCommandTest {
    @Test
    void testParse() {
        String message = "HELP\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand();
        Parser parser =
                HELPCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(HELPCommand);
        assertEquals("HELP", HELPCommand.getVerb());
        assertEquals("", HELPCommand.getSubject());
    }

    @Test
    void testParseTrailingWhitespace() {
        String message = "HELP \r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand();
        Parser parser =
                HELPCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(HELPCommand);
        assertEquals("HELP", HELPCommand.getVerb());
        assertEquals("", HELPCommand.getSubject());
    }

    @Test
    void testParseWithArgument() {
        String message = "HELP DATA\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand();
        Parser parser =
                HELPCommand.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(HELPCommand);
        assertEquals("HELP", HELPCommand.getVerb());
        assertEquals("DATA", HELPCommand.getSubject());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand();
        Serializer serializer = HELPCommand.getSerializer(context);
        serializer.serialize();
        assertEquals("HELP\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testHandler() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELPCommand HELPCommand = new SmtpHELPCommand("RCPT");
        Handler handler = HELPCommand.getHandler(context);
        handler.adjustContext(HELPCommand);

        assertTrue(context.getReversePathBuffer().isEmpty());
        assertTrue(context.getForwardPathBuffer().isEmpty());
        assertTrue(context.getMailDataBuffer().isEmpty());
    }
}
