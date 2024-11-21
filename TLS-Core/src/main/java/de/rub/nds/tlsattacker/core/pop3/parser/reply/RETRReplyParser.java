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
        List<String> lines = readWholeReply();
        this.parseReplyIndicator(reply, lines.get(0));
        for (int i = 1; i < lines.size(); i++) {
            if (!lines.get(i).equals(".")) {
                reply.addMessage(lines.get(i));
            }
        }
        if (reply.getStatusIndicator().equals("-ERR")) {
            reply.setHumanReadableMessage(lines.get(0).substring(5));
        } else if (reply.getStatusIndicator().equals("+OK")) {
            reply.setHumanReadableMessage(lines.get(0).substring(4));
        } else {
            reply.setHumanReadableMessage(lines.get(0));
        }
    }
}
