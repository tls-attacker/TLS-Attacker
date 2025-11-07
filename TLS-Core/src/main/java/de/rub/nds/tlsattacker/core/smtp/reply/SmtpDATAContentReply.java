/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpDATAContentReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpReplyHandler;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Models the content of the DATA command.
 *
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand
 * @see SmtpReply
 */
@XmlRootElement
public class SmtpDATAContentReply extends SmtpReply {
    public SmtpDATAContentReply() {
        super(SmtpCommandType.DATA_CONTENT);
    }

    @Override
    public SmtpReplyHandler<SmtpDATAContentReply> getHandler(Context smtpContext) {
        return new SmtpDATAContentReplyHandler(smtpContext.getSmtpContext());
    }
}
