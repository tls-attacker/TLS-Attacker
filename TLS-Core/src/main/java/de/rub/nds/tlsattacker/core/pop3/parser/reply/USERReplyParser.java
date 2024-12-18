/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3USERReply;
import java.io.InputStream;
import java.util.List;

public class USERReplyParser extends Pop3ReplyParser<Pop3USERReply> {
    public USERReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(Pop3USERReply reply) {
        List<String> lines = readWholeReply();
        this.parseReplyIndicator(reply, lines.get(0));
        if (reply.getStatusIndicator().equals("-ERR")) {
            String[] parts = lines.get(0).substring(5).split(" ", 2);
            reply.setUser(parts[0]);
            reply.setHumanReadableMessage(parts[1]);
        } else if (reply.getStatusIndicator().equals("+OK")) {
            String[] parts = lines.get(0).substring(4).split(" ", 2);
            reply.setUser(parts[0]);
            reply.setHumanReadableMessage(parts[1]);
        } else {
            reply.setHumanReadableMessage(lines.get(0));
        }
    }
}
