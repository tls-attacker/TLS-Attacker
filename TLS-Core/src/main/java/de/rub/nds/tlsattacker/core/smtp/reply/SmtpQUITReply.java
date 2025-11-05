/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpQUITReplyHandler;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Models the reply to the QUIT command.
 *
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpQUITCommand
 * @see SmtpReply
 */
@XmlRootElement
public class SmtpQUITReply extends SmtpReply {
    public SmtpQUITReplyHandler getHandler(SmtpContext context) {
        return new SmtpQUITReplyHandler(context);
    }
    public SmtpQUITReply() {
        super(SmtpCommandType.QUIT);
    }
}
