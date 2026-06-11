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
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpMAILCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpMAILCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class MAILCommandTest {

    @Test
    public void testStandardInput() {
        String stringMessage = "MAIL <seal@upb.de>\r\n";

        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testQuotedStringInput() {
        String stringMessage = "MAIL <\"seal\"@upb.de>\r\n";
        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testSpecialQuotedStringInput() {
        String stringMessage = "MAIL <\"seal@heal\"@upb.de>\r\n";
        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@heal@upb.de>", mail.getReversePath());
    }

    @Test
    public void testInvalidInput() {
        String stringMessage = "MAIL <seal@heal@upb.de>\r\n";
        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        assertThrows(IllegalArgumentException.class, () -> parser.parse(mail));
    }

    @Test
    public void testInvalidPathInput() {
        String stringMessage = "MAIL seal@upb.de\r\n";
        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        assertThrows(IllegalArgumentException.class, () -> parser.parse(mail));
    }

    @Test
    public void testSpecialMailParameters() {
        String stringMessage = "MAIL <seal@upb.de> SIZE [\"=\"12345]\r\n";
        SmtpMAILCommandParser parser =
                new SmtpMAILCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpMAILCommand mail = new SmtpMAILCommand();
        parser.parse(mail);
        assertEquals("MAIL", mail.getVerb());
        assertEquals("<seal@upb.de>", mail.getReversePath());
        assertEquals("SIZE", mail.getMAILparameters().get(0).getExtension().getEhloKeyword());
        assertEquals("12345", mail.getMAILparameters().get(0).getParameters());
    }

    @Test
    public void testInvalidSpecialMailParameters() {
        String[] invalidCommands = {
            "MAIL <seal@upb.de> SIZE [12345]\r\n",
            "MAIL <seal@upb.de> SIZE \"=\"12345]\r\n",
            "MAIL <seal@upb.de> SIZE [\"=\"12345\r\n",
            "MAIL <seal@upb.de> SIZE \r\n",
            "MAIL <seal@upb.de> SIZE[\"=\"12345]\r\n"
        };
        for (String command : invalidCommands) {
            SmtpMAILCommandParser parser =
                    new SmtpMAILCommandParser(
                            new ByteArrayInputStream(command.getBytes(StandardCharsets.UTF_8)));
            SmtpMAILCommand mail = new SmtpMAILCommand();
            assertThrows(IllegalArgumentException.class, () -> parser.parse(mail));
        }
    }

    @Test
    public void testSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpMAILCommand mailCommand = new SmtpMAILCommand("seal@upb.de");
        SmtpMAILCommandPreparator preparator = mailCommand.getPreparator(context.getContext());
        Serializer serializer = mailCommand.getSerializer(context.getContext());
        preparator.prepare();
        serializer.serialize();
        assertEquals("MAIL FROM:<seal@upb.de>\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpMAILCommand mailCommand = new SmtpMAILCommand("seal@upb.de");
        Handler handler = mailCommand.getHandler(context.getContext());
        handler.adjustContext(mailCommand);

        assertEquals(context.getReversePathBuffer().get(0), mailCommand.getReversePath());
        assertTrue(context.getForwardPathBuffer().isEmpty());
        assertEquals(context.getMailDataBuffer().size(), 0);
    }
}
