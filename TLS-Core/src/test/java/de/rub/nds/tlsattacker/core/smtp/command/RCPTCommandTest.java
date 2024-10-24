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
import de.rub.nds.tlsattacker.core.smtp.parser.command.RCPTCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.RCPTCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Tests for RCPT command.
 *
 * <p>Includes parsing of valid and invalid syntax, serialization, and handler.
 */
public class RCPTCommandTest {
    @Test
    void testParsePostmaster() {
        String stringMessage = "RCPT TO:<postmaster>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<postmaster>", rcpt.getParameters());
        assertEquals("postmaster", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParsePostmasterDomain() {
        String stringMessage = "RCPT TO:<seal@upb.de>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<seal@upb.de>", rcpt.getParameters());
        assertEquals("seal@upb.de", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseForwardPath() {
        String stringMessage = "RCPT TO:<@rub.com,@tue.nl:seal@abc.def.ghi>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<@rub.com,@tue.nl:seal@abc.def.ghi>", rcpt.getParameters());
        assertEquals("@rub.com,@tue.nl:seal@abc.def.ghi", rcpt.getRecipient());
        //        assertEquals("@rub.com", rcpt.getHops().get(0));
        //        assertEquals("@tue.nl", rcpt.getHops().get(1));
        //        assertEquals(2, rcpt.getHops().size());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseAnotherForwardPath() {
        String stringMessage = "RCPT TO:<@hosta.int,@jkl.org:userc@d.bar.org>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<@hosta.int,@jkl.org:userc@d.bar.org>", rcpt.getParameters());
        assertEquals("@hosta.int,@jkl.org:userc@d.bar.org", rcpt.getRecipient());
        //        assertEquals("@hosta.int", rcpt.getHops().get(0));
        //        assertEquals("@jkl.org", rcpt.getHops().get(1));
        //        assertEquals(2, rcpt.getHops().size());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseSpecialCase() {
        String stringMessage = "RCPT TO:<'*+-/=?^_`{|}~#$@nice.org>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<'*+-/=?^_`{|}~#$@nice.org>", rcpt.getParameters());
        assertEquals("'*+-/=?^_`{|}~#$@nice.org", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseIPV6() {
        String stringMessage = "RCPT TO:<test@[IPv6:2001:470:30:84:e276:63ff:fe72:3900]>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<test@[IPv6:2001:470:30:84:e276:63ff:fe72:3900]>", rcpt.getParameters());
        assertEquals("test@[IPv6:2001:470:30:84:e276:63ff:fe72:3900]", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseIPV4() {
        String stringMessage = "RCPT TO:<seal@[166.84.7.99]>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<seal@[166.84.7.99]>", rcpt.getParameters());
        assertEquals("seal@[166.84.7.99]", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseWorstCase() {
        String stringMessage = "RCPT TO:<\"\\@\\@\\@\\@\\@\"@gmail.com>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<\"\\@\\@\\@\\@\\@\"@gmail.com>", rcpt.getParameters());
        assertEquals("\"\\@\\@\\@\\@\\@\"@gmail.com", rcpt.getRecipient());
        //        assertTrue(rcpt.isValidRecipient());
    }

    @Test
    void testParseInvalidDomain() {
        String stringMessage = "RCPT TO:<nicerdicer@>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<nicerdicer@>", rcpt.getParameters());
        assertEquals("nicerdicer@", rcpt.getRecipient());
    }

    @Test
    void testParseInvalidForwardPath() {
        String stringMessage = "RCPT TO:<@,@:@gmail.com>\r\n";

        RCPTCommandParser parser =
                new RCPTCommandParser(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        SmtpRCPTCommand rcpt = new SmtpRCPTCommand();
        parser.parse(rcpt);
        assertEquals("RCPT", rcpt.getVerb());
        assertEquals("TO:<@,@:@gmail.com>", rcpt.getParameters());
        //        assertEquals("<@,@:@gmail.com>", rcpt.getRecipient());
    }

    @Test
    public void testSerialization() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRCPTCommand rcptCommand = new SmtpRCPTCommand("seal@upb.de");
        RCPTCommandPreparator preparator = rcptCommand.getPreparator(context);
        Serializer serializer = rcptCommand.getSerializer(context);
        preparator.prepare();
        serializer.serialize();
        assertEquals("RCPT TO:<seal@upb.de>\r\n", serializer.getOutputStream().toString());
    }

    @Test
    public void testHandler() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpRCPTCommand rcptCommand = new SmtpRCPTCommand("seal@upb.de");
        Handler handler = rcptCommand.getHandler(context);
        handler.adjustContext(rcptCommand);

        assertEquals(context.getRecipientBuffer().get(0), rcptCommand.getRecipient());
        assertTrue(context.getReversePathBuffer().isEmpty());
        assertTrue(context.getForwardPathBuffer().equals("seal@upb.de"));
    }
}
