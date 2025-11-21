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

/**
 * This class parses simple POP3 replies that don't require own parsing logic. The parser reads a
 * single-line reply and checks for reply indicator and human-readable message.
 *
 * @param <ReplyT> the specific POP§ reply class
 */
public class Pop3GenericReplyParser<ReplyT extends Pop3Reply> extends Pop3ReplyParser<ReplyT> {

    public Pop3GenericReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ReplyT reply) {
        parseSingleLineReply(reply);
    }
}
