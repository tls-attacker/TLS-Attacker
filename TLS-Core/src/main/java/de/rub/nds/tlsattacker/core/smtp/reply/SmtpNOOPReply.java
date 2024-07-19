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
import de.rub.nds.tlsattacker.core.smtp.preparator.NOOPReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class SmtpNOOPReply extends SmtpReply {
    // TODO: shift this to Config somehow
    private String noopMessage = "OK";

    @Override
    public NOOPReplyPreparator getPreparator(SmtpContext context) {
        return new NOOPReplyPreparator(context, this);
    }

    public String getNoopMessage() {
        return noopMessage;
    }

    public void setNoopMessage(String noopMessage) {
        this.noopMessage = noopMessage;
    }
}
