/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.RSETCommandHandler;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The RESET command aborts the current mail transaction. Buffers with senders, recipients and mail
 * data are cleared, but we store the old context for debugging purposes.
 * Example:
 * <p>C: RSET</p>
 * <p>S: 250 2.0.0 Ok</p>
 */
@XmlRootElement
public class SmtpRSETCommand extends SmtpCommand {
    private static final String COMMAND = "RSET";

    public SmtpRSETCommand() {
        super(COMMAND, null);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    @Override
    public RSETCommandHandler getHandler(SmtpContext smtpContext) {
        return new RSETCommandHandler(smtpContext);
    }
}
