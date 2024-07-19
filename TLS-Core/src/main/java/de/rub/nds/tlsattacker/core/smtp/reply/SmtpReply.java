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
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpReplySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement
public class SmtpReply extends SmtpMessage {

    protected int replyCode;
    /**
     * These are the outgoing lines for a reply. They are to be set in the prepare step of the reply preparator and the serializer.
     * They are NOT to be used for storing the abstracted contents of a message.
     */
    protected List<String> replyLines;

    // this is the human readable message part associated with the reply code
    // for a single line reply, this is the only line in the replyLines list
    protected String humanReadableMessage;

    public SmtpReply() {
        this.replyLines = new ArrayList<>();
    }

    public SmtpReply(int replyCode, List<String> replyLines) {
        this.replyCode = replyCode;
        this.replyLines = replyLines;
    }

    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        return new SmtpReplyHandler<>(smtpContext);
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpReplyParser<>(stream);
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return new SmtpReplyPreparator<>(context.getChooser(), this);
    }

    @Override
    public SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context) {
        return new SmtpReplySerializer<>(context, this);
    }

    @Override
    public String toShortString() {
        return "";
    }

    public int getReplyCode() {
        return replyCode;
    }

    public void setReplyCode(int replyCode) {
        this.replyCode = replyCode;
    }

    public List<String> getReplyLines() {
        return replyLines;
    }

    public void setReplyLines(List<String> replyLines) {
        this.replyLines = replyLines;
    }

    public String getHumanReadableMessage() {
        return humanReadableMessage;
    }

    public void setHumanReadableMessage(String humanReadableMessage) {
        this.humanReadableMessage = humanReadableMessage;
    }
}
