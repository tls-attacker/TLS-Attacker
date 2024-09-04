package de.rub.nds.tlsattacker.core.smtp.parser.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline.SmtpGenericMultilineReply;
import de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline.SmtpGenericSingleLineReply;

import java.io.InputStream;
import java.util.List;

public class SmtpGenericReplyParser<ReplyT extends SmtpReply> extends SmtpReplyParser<ReplyT> {

    public SmtpGenericReplyParser(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public void parse(ReplyT replyT) {
        if (replyT instanceof SmtpGenericSingleLineReply) parseSingleLineReply(replyT);
        else if (replyT instanceof SmtpGenericMultilineReply) parseMultiLineReply(replyT);
        else throw new ParserException("Unexpected reply object. Expected SmtpGenericSingleLineReply or SmtpGenericMultilineReply, but got: " + replyT); // TODO: handle unknown case here and save data regardless
    }

    private void parseSingleLineReply(ReplyT replyT) {
        String line = this.parseSingleLine();
        parseReplyLine(replyT, line);
    }

    private void parseMultiLineReply(ReplyT replyT) {
        List<String> lines = this.readWholeReply();
        for (String line : lines) {
            parseReplyLine(replyT, line);
        }
    }

    private void parseReplyLine(ReplyT replyT, String line) {
        this.parseReplyCode(replyT, line);

        if (line.length() <= 4) return; // fourth char is delimiter, so at least five chars are needed
        if (replyT instanceof SmtpGenericSingleLineReply) {
            ((SmtpGenericSingleLineReply) replyT).setHumanReadableMessage(line);
        } else if (replyT instanceof SmtpGenericMultilineReply) {
            ((SmtpGenericMultilineReply) replyT).addHumanReadableMessages(line);
        }
    }
}
