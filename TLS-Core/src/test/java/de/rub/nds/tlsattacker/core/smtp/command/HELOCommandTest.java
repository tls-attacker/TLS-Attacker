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
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.HELOCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class HELOCommandTest {
    @Test
    public void testParse() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELOCommand command = new SmtpHELOCommand();
        HELOCommandParser parser =
                command.getParser(
                        context,
                        new ByteArrayInputStream(
                                "HELO seal.cs.upb.de\r\n".getBytes(StandardCharsets.UTF_8)));
        parser.parse(command);
        assertEquals("HELO", command.getVerb());
        assertEquals("seal.cs.upb.de", command.getDomain());
    }

    @Test
    public void testParseDomainTrailingSpace() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELOCommand command = new SmtpHELOCommand();
        HELOCommandParser parser =
                command.getParser(
                        context,
                        new ByteArrayInputStream(
                                "HELO seal.cs.upb.de \r\n".getBytes(StandardCharsets.UTF_8)));
        parser.parse(command);
        assertEquals("HELO", command.getVerb());
        assertEquals("seal.cs.upb.de", command.getDomain());
    }

    @Test
    public void testParseInvalidDomain() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELOCommand command = new SmtpHELOCommand();
        HELOCommandParser parser =
                command.getParser(
                        context,
                        new ByteArrayInputStream(
                                "HELO seal.cs.upb.de invalid\r\n"
                                        .getBytes(StandardCharsets.UTF_8)));
        assertThrows(ParserException.class, () -> parser.parse(command));
    }

    @Test
    public void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELOCommand command = new SmtpHELOCommand("seal.cs.upb.de");
        Preparator preparator = command.getPreparator(context);
        Serializer serializer = command.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("HELO seal.cs.upb.de\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpHELOCommand command = new SmtpHELOCommand("seal.cs.upb.de");
        Handler handler = command.getHandler(context);
        handler.adjustContext(command);
        assertEquals("seal.cs.upb.de", context.getClientIdentity());
    }
}
