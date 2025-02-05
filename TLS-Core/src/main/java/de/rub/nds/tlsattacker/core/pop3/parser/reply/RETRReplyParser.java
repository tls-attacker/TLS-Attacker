/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3RETRReply;

import java.io.InputStream;
import java.util.List;

public class RETRReplyParser extends Pop3ReplyParser<Pop3RETRReply> {

    public RETRReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(Pop3RETRReply reply) {
        List<String> multiLines = parseMultiline(reply);

        if (!multiLines.isEmpty()) {
            reply.setMessages(multiLines);
        }
    }
}
