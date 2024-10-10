/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.*;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpReplyHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpReplySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class SmtpReply extends SmtpMessage {

    @ModifiableVariableProperty
    protected ModifiableInteger replyCode = new ModifiableInteger();
    @ModifiableVariableProperty
    protected ModifiableString humanReadableMessage = new ModifiableString();

    public SmtpReply() {}

    public SmtpReply(Integer replyCode) {
        this.replyCode = ModifiableVariableFactory.safelySetValue(this.replyCode, replyCode);
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
    public SmtpReplyParser<? extends SmtpReply> getParser(
            SmtpContext context, InputStream stream) {
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

    public void setReplyCode(Integer replyCode) {
        this.replyCode = ModifiableVariableFactory.safelySetValue(this.replyCode, replyCode);
    }

    public ModifiableInteger getReplyCode() {
        return replyCode;
    }

    public void setHumanReadableMessage(String humanReadableMessage) {
        this.humanReadableMessage = ModifiableVariableFactory.safelySetValue(this.humanReadableMessage, humanReadableMessage);
    }

    public ModifiableString getHumanReadableMessage() {
        return humanReadableMessage;
    }

    @Override
    public String toString() {
        char SP = ' ';
        String CRLF = "\r\n";
        StringBuilder sb = new StringBuilder();

        if (this.getReplyCode().getValue() != null) {
            sb.append(this.getReplyCode().getValue());
            sb.append(SP);
        }

        if (this.getHumanReadableMessage().getValue() != null) {
            sb.append(this.getHumanReadableMessage().getValue());
        }

        sb.append(CRLF);

        return sb.toString();
    }
}
