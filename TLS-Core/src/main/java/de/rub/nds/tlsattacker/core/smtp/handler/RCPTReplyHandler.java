/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpRCPTReply;

public class RCPTReplyHandler extends SmtpReplyHandler<SmtpRCPTReply> {
    public RCPTReplyHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }
}
