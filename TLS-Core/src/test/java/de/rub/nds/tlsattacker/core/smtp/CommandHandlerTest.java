package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;

import static org.junit.Assert.assertEquals;

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

        //FIXME: implement a specific MAILCommandHandler
//        handler = new SmtpCommandHandler(context);
    }

    @Test
    public void testadjustContext() {
        handler.adjustContext(mail);
        assertEquals(context.getReversePathBuffer(), mail.getReversePathBuffer());
    }
}
