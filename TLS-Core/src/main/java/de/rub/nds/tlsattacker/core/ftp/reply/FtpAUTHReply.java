/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.reply;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Models the reply to the {@code AUTH TLS} command (RFC 4217). A reply code of 234 indicates the
 * server is ready to begin the TLS handshake.
 *
 * @see de.rub.nds.tlsattacker.core.ftp.command.FtpAUTHCommand
 * @see FtpReply
 */
@XmlRootElement
public class FtpAUTHReply extends FtpReply {
    public FtpAUTHReply() {
        super(FtpCommandType.AUTH);
    }
}
