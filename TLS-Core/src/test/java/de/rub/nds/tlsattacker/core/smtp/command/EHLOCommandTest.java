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
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.EHLOCommandParser;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import de.rub.nds.tlsattacker.core.smtp.preparator.EHLOCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class EHLOCommandTest {
    @Test
    void testParse() {
        String stringMessage = "EHLO seal.cs.upb.de\r\n";

        EHLOCommandParser parser =
                new EHLOCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("seal.cs.upb.de", ehlo.getDomain());
    }

    @Test
    void testParseAddressLiteral() {
        String stringMessage = "EHLO 127.0.0.1\r\n";

        EHLOCommandParser parser =
                new EHLOCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        parser.parse(ehlo);
        assertEquals("EHLO", ehlo.getVerb());
        assertEquals("127.0.0.1", ehlo.getDomain());
        assertTrue(ehlo.hasAddressLiteral());
    }

    @Test
    void testParseWithoutDomain() {
        String stringMessage = "EHLO  \r\n";

        EHLOCommandParser parser =
                new EHLOCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpEHLOCommand ehlo = new SmtpEHLOCommand();
        assertThrows(ParserException.class, () -> parser.parse(ehlo));
    }

    @Test
    public void testSerialization() {
        //given an SmtpEHLOCommand see if getSerializer leads to something worthwhile
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpEHLOCommand ehloCommand = new SmtpEHLOCommand("seal.upb.de");
        EHLOCommandPreparator preparator = ehloCommand.getPreparator(context);
        Serializer serializer = ehloCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        Assertions.assertEquals("EHLO seal.upb.de\r\n", serializer.getOutputStream().toString());

    }
}
