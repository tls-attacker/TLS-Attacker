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
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpReplySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class SmtpReply extends SmtpMessage {

    protected Integer replyCode;

    public SmtpReply() {}

    public SmtpReply(Integer replyCode) {
        this.replyCode = replyCode;
    }

    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        return new SmtpReplyHandler<>(smtpContext);
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return null;
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context) {
        return new SmtpReplySerializer<>(context, this);
    }

    @Override
    public String toShortString() {
        return "";
    }

    public void setReplyCode(Integer replyCode) {
        this.replyCode = replyCode;
    }

    public int getReplyCode() {
        return replyCode;
    }
}
