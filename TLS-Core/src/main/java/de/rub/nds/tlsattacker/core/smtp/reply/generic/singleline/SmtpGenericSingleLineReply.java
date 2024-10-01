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
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import java.io.InputStream;

public abstract class SmtpGenericSingleLineReply extends SmtpReply {
    String humanReadableMessage;

    public void setHumanReadableMessage(String humanReadableMessage) {
        this.humanReadableMessage = humanReadableMessage;
    }

    public String getHumanReadableMessage() {
        return humanReadableMessage;
    }

    @Override
    public SmtpGenericReplyParser<SmtpGenericSingleLineReply> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public String toString() {
        char SP = ' ';
        String CRLF = "\r\n";
        StringBuilder sb = new StringBuilder();

        if (this.replyCode != null) {
            sb.append(this.replyCode);
            sb.append(SP);
        }

        if (this.humanReadableMessage != null) {
            sb.append(humanReadableMessage);
        }

        sb.append(CRLF);

        return sb.toString();
    }
}
