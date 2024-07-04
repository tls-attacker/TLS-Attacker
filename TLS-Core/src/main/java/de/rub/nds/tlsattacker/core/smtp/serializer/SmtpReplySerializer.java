package de.rub.nds.tlsattacker.core.smtp.serializer;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

public class SmtpReplySerializer<ReplyT extends SmtpReply> extends SmtpMessageSerializer<ReplyT> {

    // modeled after their usage in RFC 5321
    private static final String SP = " ";
    private static final String CRLF = "\r\n";

    private final SmtpReply reply;

    public SmtpReplySerializer(SmtpContext context, ReplyT smtpReply) {
        super(smtpReply, context);
        this.reply = smtpReply;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder builder = new StringBuilder();

        int replyCode = this.reply.getReplyCode();
        for (int i = 0; i < this.reply.getReplyLines().size() - 1; i++) {
            builder.append(replyCode).append("-");
            builder.append(this.reply.getReplyLines().get(i));
            builder.append(CRLF);
        }
        builder.append(replyCode)
                .append(SP)
                .append(this.reply.getReplyLines().get(this.reply.getReplyLines().size() - 1))
                .append(CRLF);
        byte[] output = builder.toString().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
