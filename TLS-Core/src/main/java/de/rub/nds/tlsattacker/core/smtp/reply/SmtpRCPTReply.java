package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.RCPTReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.RCPTReplyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class SmtpRCPTReply extends SmtpReply {
    private String message;

    // TODO: move to SmtpReply class
    private boolean valid = true;

    public SmtpRCPTReply() {
        super();
        // set reply code for success
        this.setReplyCode(250);
    }

    public SmtpRCPTReply(int replyCode, List<String> replyLines) {
        super();
        this.setReplyCode(replyCode);
        this.setReplyLines(replyLines);
    }

    public SmtpRCPTReply(int replyCode, String message) {
        super();
        this.setReplyCode(replyCode);
        this.setMessage(message);
        List<String> replyLines = new ArrayList<>();
        replyLines.add(message);
        this.setReplyLines(replyLines);
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    @Override
    public RCPTReplyParser getParser(SmtpContext context, InputStream stream) {
        return new RCPTReplyParser(stream);
    }

    @Override
    public RCPTReplyPreparator getPreparator(SmtpContext context) {
        return new RCPTReplyPreparator(context, this);
    }
}


