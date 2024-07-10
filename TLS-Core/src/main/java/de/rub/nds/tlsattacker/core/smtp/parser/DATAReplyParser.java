package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAReply;

import java.io.InputStream;
import java.util.List;

public class DATAReplyParser extends SmtpReplyParser<SmtpDATAReply>{

    public DATAReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAReply dataReply) {
        List<String> lines = parseAllLines();
    }

}
