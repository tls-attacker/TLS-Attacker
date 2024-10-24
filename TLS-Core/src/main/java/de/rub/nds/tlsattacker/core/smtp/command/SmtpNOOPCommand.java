/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Implements the NOOP command, which does nothing. Example: <br>
 * C: NOOP <br>
 * S: 250 2.0.0 Ok
 */
@XmlRootElement
public class SmtpNOOPCommand extends SmtpCommand {
    private static final String COMMAND = "NOOP";

    public SmtpNOOPCommand() {
        super(COMMAND);
    }
}
