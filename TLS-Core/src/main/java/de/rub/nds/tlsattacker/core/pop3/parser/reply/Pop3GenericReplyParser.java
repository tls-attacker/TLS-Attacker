/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Used to parse simple POP3 replies that don't require own parsing logic. The parser reads the
 * whole reply and checks for the replyIndicator and human-readable message
 *
 * @param <ReplyT> the specific POP§ reply class
 */
public class Pop3GenericReplyParser<ReplyT extends Pop3Reply> extends Pop3ReplyParser<ReplyT> {

    public Pop3GenericReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ReplyT reply) {
        String line = parseSingleLine();
        parseReplyIndicator(reply, line);

        String humanReadableMessage = "";

        if (line.startsWith("+OK") & line.length() > 3) humanReadableMessage = line.substring(4);
        else if (line.startsWith("-ERR") & line.length() > 4) humanReadableMessage = line.substring(5);

        reply.setHumanReadableMessage(humanReadableMessage);
    }
}
