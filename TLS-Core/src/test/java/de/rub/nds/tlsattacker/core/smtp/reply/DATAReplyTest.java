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
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpDATAReply;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class DATAReplyTest {
    @Test
    void testParse() {
        String message = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";

        SmtpDATAReply dataReply = new SmtpDATAReply();
        SmtpGenericReplyParser<SmtpDATAReply> dataReplyParser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));

        dataReplyParser.parse(dataReply);
        assertEquals(354, dataReply.getReplyCode());
        assertEquals(
                "Start mail input; end with <CRLF>.<CRLF>", dataReply.getHumanReadableMessage());
    }

    @Test
    void testInvalidParse() {
        String message = "111 test\r\n";
        SmtpDATAReply dataReply = new SmtpDATAReply();
        SmtpGenericReplyParser<SmtpDATAReply> dataReplyParser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));

        assertDoesNotThrow(() -> dataReplyParser.parse(dataReply));
        assertEquals(dataReply.getReplyCode(), 111);
        assertEquals(dataReply.getHumanReadableMessage(), "test");
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpDATAReply dataReply = new SmtpDATAReply();
        dataReply.setReplyCode(354);
        dataReply.setHumanReadableMessage("Start mail input; end with <CRLF>.<CRLF>");

        Serializer<?> serializer = dataReply.getSerializer(context);
        serializer.serialize();
        assertEquals(
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                serializer.getOutputStream().toString());
    }
}
