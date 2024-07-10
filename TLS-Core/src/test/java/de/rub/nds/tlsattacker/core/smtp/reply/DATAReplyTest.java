/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.DATAReplyParser;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class DATAReplyTest {
    @Test
    void testParse() {
        String message = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAReply dataReply = new SmtpDATAReply();
        DATAReplyParser dataReplyParser =
                dataReply.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        dataReplyParser.parse(dataReply);
        assertEquals(354, dataReply.getReplyCode());
        assertEquals("Start mail input; end with <CRLF>.<CRLF>", dataReply.getDataMessage());
    }

    @Test
    void invalidParse() {
        String message = "111 test\r\n";
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAReply dataReply = new SmtpDATAReply();
        DATAReplyParser dataReplyParser =
                dataReply.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));

        assertThrows(ParserException.class, () -> dataReplyParser.parse(dataReply));
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAReply dataReply = new SmtpDATAReply();
        dataReply.setReplyCode(354);
        dataReply.setDataMessage("Start mail input; end with <CRLF>.<CRLF>");
        Preparator preparator = dataReply.getPreparator(context);
        preparator.prepare();
        Serializer serializer = dataReply.getSerializer(context);
        serializer.serialize();
        assertEquals(
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                serializer.getOutputStream().toString());
    }
}
