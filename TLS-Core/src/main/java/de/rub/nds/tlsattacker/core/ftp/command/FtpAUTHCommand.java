/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.command;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Implements the {@code AUTH TLS} command used to start a TLS session on the FTP control connection
 * (RFC 4217). It does not execute the actual handshake, but communicates to the server that a TLS
 * handshake is coming. Works hand in hand with the STARTTLS workflow. Example:
 *
 * <pre>
 * C: AUTH TLS
 * S: 234 AUTH command ok. Initializing TLS Connection.
 * </pre>
 */
@XmlRootElement
public class FtpAUTHCommand extends FtpCommand {

    /** Default security mechanism argument requested by the AUTH command. */
    public static final String DEFAULT_MECHANISM = "TLS";

    public FtpAUTHCommand() {
        super(FtpCommandType.AUTH, DEFAULT_MECHANISM);
    }
}
