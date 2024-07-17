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

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.EHLOCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class EHLOCommandTest {

    @Test
    void testParse() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        String stringMessage = "EHLO seal.cs.upb.de\r\n";

        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("seal.cs.upb.de", ehlo.getClientIdentity());
    }

    @Test
    void testDomainTrailingSpace() {
        String stringMessage = "EHLO seal.cs.upb.de \r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();

        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("seal.cs.upb.de", ehlo.getClientIdentity());
    }

    @Test
    void testParseInvalidDomain() {
        String stringMessage = "EHLO seal.cs.upb.de invalid\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();

        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("seal.cs.upb.de invalid", ehlo.getClientIdentity());
    }

    @Test
    void testParseAddressLiteral() {
        String stringMessage = "EHLO [127.0.0.1]\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();

        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("127.0.0.1", ehlo.getClientIdentity());
        assertTrue(ehlo.hasAddressLiteral());
    }

    @Test
    void testParseMalformedAddressLiteral() {
        String stringMessage = "EHLO [1.2.3. ]\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));

        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("1.2.3. ", ehlo.getClientIdentity());
    }

    @Test
    void testParseWithoutDomain() {
        String stringMessage = "EHLO  \r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();

        EHLOCommandParser parser =
                ehlo.getParser(
                        context,
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        assertThrows(ParserException.class, () -> parser.parse(ehlo));
    }

    @Test
    public void parseAddressLiteralTest() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand command = new SmtpEHLOCommand();
        EHLOCommandParser parser =
                command.getParser(
                        context,
                        new ByteArrayInputStream(
                                "EHLO [127.0.0.1]\r\n".getBytes(StandardCharsets.UTF_8)));
        parser.parse(command);
        assertEquals("127.0.0.1", command.getClientIdentity());
        assertTrue(command.hasAddressLiteral());
    }

    @Test
    public void testDomainSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehloCommand = new SmtpEHLOCommand("seal.upb.de");
        EHLOCommandPreparator preparator = ehloCommand.getPreparator(context);
        Serializer serializer = ehloCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("EHLO seal.upb.de\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testAddressLiteralSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehloCommand = new SmtpEHLOCommand("127.0.0.1");
        EHLOCommandPreparator preparator = ehloCommand.getPreparator(context);
        Serializer serializer = ehloCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("EHLO [127.0.0.1]\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehloCommand = new SmtpEHLOCommand("seal.upb.de");
        Handler handler = ehloCommand.getHandler(context);

        handler.adjustContext(ehloCommand);

        assertEquals(context.getClientIdentity(), ehloCommand.getClientIdentity());
    }
}
