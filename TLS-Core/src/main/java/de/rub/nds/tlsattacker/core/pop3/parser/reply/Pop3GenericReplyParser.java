package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Used to parse simple POP3 replies that don't require own parsing logic.
 * The parser reads the whole reply and checks for the replyIndicator and human-readable message
 * @param <ReplyT> the specific POP§ reply class
 */

public class Pop3GenericReplyParser<ReplyT extends Pop3Reply> extends Pop3ReplyParser<ReplyT> {

    public Pop3GenericReplyParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ReplyT reply) {
        List<String> lines = this.readWholeReply();
        List<String> message = new ArrayList<>();
        this.parseReplyIndicator(reply, lines.get(0));
        for (int i = 1; i < lines.size(); i++) {
            message.add(lines.get(i));
        }

        reply.setHumanReadableMessage(message);
    }

}
