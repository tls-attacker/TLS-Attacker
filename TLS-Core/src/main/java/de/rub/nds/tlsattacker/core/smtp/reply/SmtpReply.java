/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.*;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpReplySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Base class for modelling replies to SMTP commands. Usually consists of status code and
 * human-readable message associated with it. For example: <br>
 * C: MAIL FROM:&lt;seal@upb.de&gt; <br>
 * S: 250 Ok
 */
@XmlRootElement
public class SmtpReply extends SmtpMessage {

    protected Integer replyCode = 0; // some invalid value to indicate that it was not set
    //    protected String humanReadableMessage;
    protected List<String> humanReadableMessages = new ArrayList<>();

    // hide from the user that there can be multiple human-readable messages
    // (e.g. for multiline replies)
    public List<String> getHumanReadableMessages() {
        return humanReadableMessages;
    }

    public void setHumanReadableMessages(List<String> humanReadableMessages) {
        this.humanReadableMessages = humanReadableMessages;
    }

    public void setHumanReadableMessage(String message) {
        this.humanReadableMessages = new ArrayList<>(List.of(message));
    }

    public String getHumanReadableMessage() {
        return this.humanReadableMessages.get(0);
    }

    public boolean isMultiline() {
        return this.humanReadableMessages.size() > 1;
    }

    public SmtpReply() {
        this.humanReadableMessages = new ArrayList<>();
    }

    public SmtpReply(Integer replyCode) {
        // allows a user to create a custom reply with a very specific (perhaps standard-violating)
        // reply code
        // we do not currently do this in the codebase, but it is a possibility, so we allow it
        super();
        this.replyCode = replyCode;
    }

    @Override
    public SmtpReplyHandler<? extends SmtpReply> getHandler(SmtpContext smtpContext) {
        return new SmtpReplyHandler<>(smtpContext);
    }

    @Override
    public SmtpReplyPreparator<? extends SmtpReply> getPreparator(SmtpContext context) {
        return new SmtpReplyPreparator<>(context.getChooser(), this);
    }

    @Override
    public SmtpReplyParser<? extends SmtpReply> getParser(SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public SmtpReplySerializer<? extends SmtpReply> getSerializer(SmtpContext context) {
        return new SmtpReplySerializer<>(context, this);
    }

    @Override
    public String toShortString() {
        return "SMTP_REPLY";
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getReplyCode())
                .append(" ")
                .append(SmtpMappingUtil.getMatchingCommand(this).getVerb())
                .append("Reply");
        return sb.toString();
    }

    public void setReplyCode(Integer replyCode) {
        this.replyCode = replyCode;
    }

    public int getReplyCode() {
        return replyCode;
    }

    //    public void setHumanReadableMessage(String humanReadableMessage) {
    //        this.humanReadableMessage = humanReadableMessage;
    //    }

    public String serialize() {
        char SP = ' ';
        char DASH = '-';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();
        String replyCodeString =
                this.replyCode != null ? String.format("%03d", this.replyCode) : "";
        String replyCodePrefix = this.replyCode != null ? replyCodeString + DASH : "";

        for (int i = 0; i < this.humanReadableMessages.size() - 1; i++) {
            sb.append(replyCodePrefix);
            sb.append(this.humanReadableMessages.get(i));
            sb.append(CRLF);
        }

        sb.append(replyCodeString);
        // partly workaround for uninitialized humanReadableMessages (which should not happen), but
        // also more in line with standard: Empty messages are not intended, but recommended to
        // accept
        if (!this.humanReadableMessages.isEmpty()) {
            sb.append(SP);
            sb.append(this.humanReadableMessages.get(this.humanReadableMessages.size() - 1));
        }
        sb.append(CRLF);

        return sb.toString();
    }
}
