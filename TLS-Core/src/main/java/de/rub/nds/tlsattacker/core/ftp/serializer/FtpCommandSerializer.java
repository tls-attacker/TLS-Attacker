/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.serializer;

import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import java.nio.charset.StandardCharsets;

/**
 * Serializes FTP commands on the most basic level: keyword, space, arguments, CRLF.
 *
 * @param <CommandT> The FTP command to serialize.
 */
public class FtpCommandSerializer<CommandT extends FtpCommand>
        extends FtpMessageSerializer<CommandT> {

    private final FtpCommand command;

    public FtpCommandSerializer(CommandT ftpCommand, FtpContext context) {
        super(ftpCommand, context);
        this.command = ftpCommand;
    }

    @Override
    protected byte[] serializeBytes() {
        byte[] output = this.command.serialize().getBytes(StandardCharsets.US_ASCII);
        appendBytes(output);
        return getAlreadySerialized();
    }
}
