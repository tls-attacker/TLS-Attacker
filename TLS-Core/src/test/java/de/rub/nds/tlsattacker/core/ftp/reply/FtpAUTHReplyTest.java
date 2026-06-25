/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.reply;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.ftp.parser.reply.FtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

public class FtpAUTHReplyTest {

    @Test
    void testParse() {
        FtpAUTHReply authReply = new FtpAUTHReply();
        String message = "234 AUTH command ok. Initializing TLS Connection.\r\n";

        FtpGenericReplyParser<FtpAUTHReply> parser =
                new FtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(authReply);

        assertEquals(234, authReply.getReplyCode());
        assertEquals(
                "AUTH command ok. Initializing TLS Connection.",
                authReply.getHumanReadableMessage());
    }

    @Test
    void testParseMultiline() {
        FtpAUTHReply authReply = new FtpAUTHReply();
        String message = "234-First line\r\n234 Last line\r\n";

        FtpGenericReplyParser<FtpAUTHReply> parser =
                new FtpGenericReplyParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(authReply);

        assertEquals(234, authReply.getReplyCode());
        List<String> messages = authReply.getHumanReadableMessages();
        assertEquals(2, messages.size());
        assertEquals("First line", messages.get(0));
        assertEquals("Last line", messages.get(1));
    }

    @Test
    void testSerialize() {
        FtpContext context = new FtpContext(new Context(new State(), new OutboundConnection()));
        FtpAUTHReply authReply = new FtpAUTHReply();
        authReply.setReplyCode(234);
        authReply.setHumanReadableMessage("Proceed with negotiation");
        FtpMessageSerializer<?> serializer = authReply.getSerializer(context.getContext());

        serializer.serialize();

        assertEquals("234 Proceed with negotiation\r\n", serializer.getOutputStream().toString());
    }
}
