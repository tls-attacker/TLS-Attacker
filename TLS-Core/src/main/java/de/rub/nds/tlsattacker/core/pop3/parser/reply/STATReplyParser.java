/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3STATReply;
import java.io.InputStream;
import java.util.List;

public class STATReplyParser extends Pop3ReplyParser<Pop3STATReply> {

    public STATReplyParser(InputStream stream) {
        super(stream);
    }

    // Ignore MultiLine for now as STAT reply is specified as single line
    @Override
    public void parse(Pop3STATReply reply) {
        List<String> lines = readWholeReply();
        this.parseReplyIndicator(reply, lines.get(0));
        String[] parts = lines.get(0).split(" ");
        if (parts.length == 2) {
            reply.setMessages(parts[1]);
        } else if (parts.length == 3) {
            reply.setMessages(parts[1]);
            reply.setOctets(parts[2]);
        }
        if (reply.getStatusIndicator().equals("-ERR")) {
            reply.setHumanReadableMessage(lines.get(0).substring(5));
        }
    }
}
