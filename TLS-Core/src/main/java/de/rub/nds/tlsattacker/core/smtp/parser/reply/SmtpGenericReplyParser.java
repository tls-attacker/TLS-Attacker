/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline.SmtpGenericMultilineReply;
import java.io.InputStream;
import java.util.List;

public class SmtpGenericReplyParser<ReplyT extends SmtpReply> extends SmtpReplyParser<ReplyT> {

    public SmtpGenericReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(ReplyT replyT) {
        List<String> lines = this.readWholeReply();

        for (String line : lines) {
            parseReplyLine(replyT, line);
        }
    }

    private void parseReplyLine(ReplyT replyT, String line) {
        this.parseReplyCode(replyT, line);

        if (line.length() <= 4)
            return; // fourth char is delimiter, so at least five chars are needed

        if (replyT instanceof SmtpGenericMultilineReply) {
            ((SmtpGenericMultilineReply) replyT).addHumanReadableMessages(line.substring(4));
        } else {
            replyT.setHumanReadableMessage(line.substring(4));
        }
    }
}
