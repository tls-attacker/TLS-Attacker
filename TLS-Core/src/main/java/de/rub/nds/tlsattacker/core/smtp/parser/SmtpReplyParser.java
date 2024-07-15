/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SmtpReplyParser<ReplyT extends SmtpReply> extends SmtpMessageParser<ReplyT> {
    public SmtpReplyParser(InputStream stream) {
        super(stream);
    }

    /**
     * Default implementation of the parse method. Only the status code is parsed.
     *
     * @param replyT object that should be filled with content
     */
    @Override
    public void parse(ReplyT replyT) {
        String line = parseSingleLine();
        String[] replyParts = line.split(" ", 2);
        if (replyParts.length < 2) {
            throw new ParserException(
                    "Could not parse SmtpReply. Expected at least 2 parts in the reply but got: "
                            + line);
        }
        try {
            replyT.setReplyCode(Integer.parseInt(replyParts[0]));
        } catch (NumberFormatException e) {
            throw new ParserException(
                    "Could not parse SmtpReply. Could not parse reply code: " + replyParts[0]);
        }
    }

    public List<String> readWholeReply() {
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = parseSingleLine()) != null) {
            lines.add(line);
            if (isEndOfReply(line)) {
                break;
            }
        }
        return lines;
    }

    private boolean isEndOfReply(String line) {
        return line.matches("\\d{3} .*");
    }
}
