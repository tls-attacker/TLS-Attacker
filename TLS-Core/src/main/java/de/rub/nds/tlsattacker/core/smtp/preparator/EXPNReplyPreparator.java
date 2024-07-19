/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEXPNReply;

public class EXPNReplyPreparator extends SmtpReplyPreparator<SmtpEXPNReply> {
    public EXPNReplyPreparator(SmtpContext context, SmtpEXPNReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        getObject().setReplyLines(getObject().getLineContents());
    }
}
