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
        List<String> multiLines = parseReply(reply);

        // case: single line response contains necessary data
        if (multiLines.isEmpty()) parseMessageData(reply);
    }

    public void parseMessageData(Pop3STATReply reply) {
        String[] parts = reply.getHumanReadableMessage().split(" ");
        if (parts.length == 2) {
            reply.setNumberOfMessages(parts[0]);
            reply.setMailDropSize(parts[1]);
        }
    }
}
