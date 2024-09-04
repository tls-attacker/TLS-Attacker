/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.QUITReplyHandler;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpQUITReply extends SmtpGenericSingleLineReply {
    public QUITReplyHandler getHandler(SmtpContext context) {
        return new QUITReplyHandler(context);
    }
}
