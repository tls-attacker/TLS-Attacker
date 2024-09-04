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

import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpNOOPReply;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class NOOPReplyTest {

    @Test
    public void testParseSimple() {
        String stringMessage = "250 NOOP acknowledged\r\n";

        SmtpNOOPReply noop = new SmtpNOOPReply();
        SmtpGenericReplyParser<SmtpNOOPReply> parser =
                new SmtpGenericReplyParser<>(
                        new ByteArrayInputStream(stringMessage.getBytes(StandardCharsets.UTF_8)));
        parser.parse(noop);

        assertEquals(250, noop.getReplyCode());
        assertEquals("NOOP acknowledged", noop.getHumanReadableMessage());
    }
}
