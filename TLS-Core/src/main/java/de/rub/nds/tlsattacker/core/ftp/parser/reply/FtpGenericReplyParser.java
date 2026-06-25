/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.parser.reply;

import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses simple FTP replies that don't require their own parsing logic. Reads the whole reply and
 * captures the reply code and the human-readable message(s).
 *
 * @param <ReplyT> the specific FTP reply class, i.e. a child of FtpReply
 */
public class FtpGenericReplyParser<ReplyT extends FtpReply> extends FtpReplyParser<ReplyT> {

    public FtpGenericReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(ReplyT reply) {
        List<String> rawLines = this.readWholeReply();

        List<String> messages = new ArrayList<>();
        for (String line : rawLines) {
            this.parseReplyCode(reply, line);
            if (line.length() <= 4) {
                // "NNN" or "NNN " carries no human-readable text
                continue;
            }
            // fourth char is the delimiter (space or dash), text follows
            messages.add(line.substring(4));
        }

        reply.setHumanReadableMessages(messages);
    }
}
