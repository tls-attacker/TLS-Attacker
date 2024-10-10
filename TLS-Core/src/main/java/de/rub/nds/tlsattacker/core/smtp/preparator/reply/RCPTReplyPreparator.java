/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.SmtpRCPTReply;

public class RCPTReplyPreparator extends SmtpReplyPreparator<SmtpRCPTReply> {
    public RCPTReplyPreparator(SmtpContext context, SmtpRCPTReply reply) {
        super(context.getChooser(), reply);
    }

//    /**
//     * Prepares a RCPT reply by setting reply code and reply lines.
//     */
//    @Override
//    public void prepare() {
//        List<String> replyLines = new ArrayList<>();
//        String message = getObject().getMessage();
//        replyLines.add(message);
//        this.getObject().setReplyLines(replyLines);
//    }
}
