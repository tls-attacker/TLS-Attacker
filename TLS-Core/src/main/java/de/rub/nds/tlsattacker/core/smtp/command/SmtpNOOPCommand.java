/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Implements the NOOP command, which does nothing. Example: <br>
 *
 * <pre>
 * C: NOOP
 * S: 250 2.0.0 Ok
 * </pre>
 */
@XmlRootElement
public class SmtpNOOPCommand extends SmtpCommand {
    public SmtpNOOPCommand() {
        super(SmtpCommandType.NOOP);
    }
}
