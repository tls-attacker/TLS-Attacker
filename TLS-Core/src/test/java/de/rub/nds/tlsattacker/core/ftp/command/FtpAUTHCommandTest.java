/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.command;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpCommandParser;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class FtpAUTHCommandTest {

    @Test
    void testParse() {
        FtpAUTHCommand authCommand = new FtpAUTHCommand();
        String message = "AUTH TLS\r\n";

        FtpCommandParser<FtpAUTHCommand> parser =
                new FtpCommandParser<>(
                        new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
        parser.parse(authCommand);

        assertEquals("TLS", authCommand.getArguments());
        assertEquals("AUTH", authCommand.getKeyword());
    }

    @Test
    void testSerialize() {
        FtpContext context = new FtpContext(new Context(new State(), new OutboundConnection()));
        FtpAUTHCommand authCommand = new FtpAUTHCommand();
        FtpMessageSerializer<?> serializer = authCommand.getSerializer(context.getContext());

        serializer.serialize();

        assertEquals("AUTH TLS\r\n", serializer.getOutputStream().toString());
    }
}
