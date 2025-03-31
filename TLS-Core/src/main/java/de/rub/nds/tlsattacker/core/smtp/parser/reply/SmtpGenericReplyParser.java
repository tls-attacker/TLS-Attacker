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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The SmtpGenericReplyParser is used to parse simple SMTP replies that don't require their own
 * parsing logic. The parser reads the whole reply and checks for reply codes and human-readable
 * messages.
 *
 * @param <ReplyT> The specific SMTP reply class, i.e. child class of SmtpReply.
 */
public class SmtpGenericReplyParser<ReplyT extends SmtpReply> extends SmtpReplyParser<ReplyT> {

    public SmtpGenericReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(ReplyT replyT) {
        List<String> rawLines = this.readWholeReply();

        List<String> reply = new ArrayList<>();
        for (String line : rawLines) {
            this.parseReplyCode(replyT, line);
            if (line.length() <= 4) {
                return; // fourth char is delimiter, so at least five chars are needed
            }
            reply.add(line.substring(4));
        }

        replyT.setHumanReadableMessages(reply);
    }
}
