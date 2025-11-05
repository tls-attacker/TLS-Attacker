/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import java.io.InputStream;

public class Pop3UnterminatedReply extends Pop3UnknownReply {

    @Override
    public Pop3ReplyParser<? extends Pop3Message> getParser(
            Pop3Context context, InputStream stream) {
        return new Pop3ReplyParser<Pop3UnterminatedReply>(stream) {
            @Override
            public void parse(Pop3UnterminatedReply reply) {
                try {
                    this.parseTillEnd();
                } catch (Exception e) {
                    throw new ParserException(
                            "Pop3UnterminatedReply emptied stream and raised an exception", e);
                }
            }
        };
    }
}
