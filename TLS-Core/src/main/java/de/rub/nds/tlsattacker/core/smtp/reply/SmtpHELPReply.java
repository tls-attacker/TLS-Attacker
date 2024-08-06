package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.HELPReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.HELPReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.HELPReplyPreparator;

import java.io.InputStream;

/**
 * The HELP response contains helpful information for the client.
 * It consists of a reply code and human-readable messaqe. If the
 * reply does not follow that syntax, the validSyntax parameter is
 * set to False.
 */
public class SmtpHELPReply extends SmtpReply {
    private boolean validReply;

    private String helpMessage;

    public SmtpHELPReply() {
        super();
        this.validReply = true;
        this.replyCode = 214;
        this.helpMessage = "Commands: HELO EHLO MAIL RCPT DATA VRFY NOOP QUIT HELP EXPN";
    }

    public String getHelpMessage() {
        return helpMessage;
    }

    public void setHelpMessage(String helpMessage) {
        this.helpMessage = helpMessage;
    }

    public boolean isValidReply() {
        return validReply;
    }

    public void setValidReply(boolean validReply) {
        this.validReply = validReply;
    }

    @Override
    public HELPReplyParser getParser(SmtpContext context, InputStream stream) {
        return new HELPReplyParser(stream);
    }

    public HELPReplyPreparator getPreparator(SmtpContext context) {
        return new HELPReplyPreparator(context, this);
    }

    public HELPReplyHandler getHandler(SmtpContext context) {
        return new HELPReplyHandler(context);
    }
}

