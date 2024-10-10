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
import de.rub.nds.tlsattacker.core.smtp.handler.RESETCommandHandler;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The RESET command aborts the current mail transaction. Buffers with senders, recipients and mail
 * data are cleared
 */
@XmlRootElement
public class SmtpRESETCommand extends SmtpCommand {
    private static final String COMMAND = "RSET";

    public SmtpRESETCommand() {
        super(COMMAND, null);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    @Override
    public RESETCommandHandler getHandler(SmtpContext smtpContext) {
        return new RESETCommandHandler(smtpContext);
    }
}
