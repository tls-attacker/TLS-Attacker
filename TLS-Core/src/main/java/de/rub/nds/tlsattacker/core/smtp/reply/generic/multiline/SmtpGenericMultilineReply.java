/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public abstract class SmtpGenericMultilineReply extends SmtpReply {

    List<String> humanReadableMessages = new ArrayList<>();

    public List<String> getHumanReadableMessages() {
        return humanReadableMessages;
    }

    public void setHumanReadableMessages(List<String> humanReadableMessages) {
        this.humanReadableMessages = humanReadableMessages;
    }

    public void addHumanReadableMessages(String humanReadableMessage) {
        this.humanReadableMessages.add(humanReadableMessage);
    }

    @Override
    public SmtpGenericReplyParser<SmtpGenericMultilineReply> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public String toString() {
        String SP = " ";
        String DASH = "-";
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < this.humanReadableMessages.size() - 1; i++) {
            sb.append(this.getReplyCode().getValue() + DASH);
            sb.append(this.humanReadableMessages.get(i));
            sb.append(CRLF);
        }

        sb.append(this.getReplyCode().getValue());
        sb.append(SP);
        sb.append(this.humanReadableMessages.get(this.humanReadableMessages.size() - 1));
        sb.append(CRLF);

        return sb.toString();
    }
}
