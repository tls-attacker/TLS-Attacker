package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;

import java.io.InputStream;

public class Pop3UnterminatedReply extends Pop3UnknownReply {
    @Override
    public Pop3ReplyParser<? extends Pop3Message> getParser(Pop3Context context, InputStream stream) {
        return new Pop3ReplyParser<Pop3UnterminatedReply>(stream) {
            @Override
            public void parse(Pop3UnterminatedReply reply) {
                try {
                    this.parseTillEnd();
                } catch (Exception e) {
                    throw new ParserException("Pop3UnterminatedReply emptied stream and raised an exception", e);
                }
            }
        };
    }
}
