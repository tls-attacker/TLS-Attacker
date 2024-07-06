/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import static org.junit.Assert.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import org.junit.Before;
import org.junit.Test;

public class CommandHandlerTest {

    private SmtpContext context;
    private SmtpMAILCommand mail;
    private SmtpCommandHandler handler;

    @Before
    public void setUp() {
        context = new Context(new State(new Config()), new OutboundConnection()).getSmtpContext();

        String message = "MAIL rub@ubp.de\r\n";
        MAILCommandParser parser =
                new MAILCommandParser(
                        new ByteArrayInputStream(message.getBytes(Charset.forName("UTF-8"))));
        mail = new SmtpMAILCommand();
        parser.parse(mail);

        // FIXME: implement a specific MAILCommandHandler
        //        handler = new SmtpCommandHandler(context);
    }

    @Test
    public void testadjustContext() {
        handler.adjustContext(mail);
        assertEquals(context.getReversePathBuffer(), mail.getReversePathBuffer());
    }
}
