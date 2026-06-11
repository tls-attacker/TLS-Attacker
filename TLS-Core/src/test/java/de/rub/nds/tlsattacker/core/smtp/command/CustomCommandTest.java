/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

public class CustomCommandTest {
    @Test
    public void testSerializeCustom() {
        SmtpContext context = new SmtpContext(new Context(new State(), new OutboundConnection()));
        SmtpCommand custom = new SmtpCommand("WOW", "such command");

        Preparator<?> preparator = custom.getPreparator(context.getContext());
        Serializer<?> serializer = custom.getSerializer(context.getContext());
        preparator.prepare();
        serializer.serialize();

        assertEquals("WOW such command\r\n", serializer.getOutputStream().toString());
    }
}
