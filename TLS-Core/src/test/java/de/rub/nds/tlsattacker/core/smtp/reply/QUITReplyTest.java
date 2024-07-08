/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class QUITReplyTest {
    @Test
    void testParse() {
        String message = "221 byebye\r\n";

        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpQUITReply quitReply = new SmtpQUITReply();
        Parser parser =
                quitReply.getParser(
                        context,
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(quitReply);
        assertEquals(221, quitReply.getReplyCode());
    }

    @Test
    void testSerialize() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpQUITReply quitReply = new SmtpQUITReply();
        Preparator preparator = quitReply.getPreparator(context);
        preparator.prepare();
        Serializer serializer = quitReply.getSerializer(context);
        serializer.serialize();
        assertEquals("221 arf arf\r\n", serializer.getOutputStream().toString());
    }

    @Test
    void testHandle() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpQUITReply quitReply = new SmtpQUITReply();
        quitReply.getHandler(context).adjustContext(quitReply);
        assertTrue(context.isServerAcknowledgedClose());
    }
}
