package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.parser.HELPReplyParser;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SmtpHELPReply extends SmtpReply {
    private int replyCode;
    private String replyMessage;

    public SmtpHELPReply() {
        super();
    }

    @Override
    public HELPReplyParser getParser(SmtpContext context, InputStream stream) {
        return new HELPReplyParser(stream);
    }

    public int getReplyCode() {
        return replyCode;
    }

    public void setReplyCode(int replyCode) {
        this.replyCode = replyCode;
    }

    public String getReplyMessage() {
        return replyMessage;
    }

    public void setReplyMessage(String replyMessage) {
        this.replyMessage = replyMessage;
    }
}

