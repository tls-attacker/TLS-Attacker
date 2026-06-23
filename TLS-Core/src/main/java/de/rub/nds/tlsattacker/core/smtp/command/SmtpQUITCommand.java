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
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpQUITCommandHandler;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The QUIT command causes the server to send an 221 OK reply, and then close the transmission
 * channel. The client SHOULD NOT close the transmission channel until it receives the reply.
 * Example:
 *
 * <pre>
 * C: QUIT
 * S: 221 2.0.0 Bye
 * </pre>
 */
@XmlRootElement
public class SmtpQUITCommand extends SmtpCommand {
    public SmtpQUITCommand() {
        super(SmtpCommandType.QUIT);
    }

    @Override
    public SmtpQUITCommandHandler getHandler(Context smtpContext) {
        return new SmtpQUITCommandHandler(smtpContext.getSmtpContext());
    }
}
