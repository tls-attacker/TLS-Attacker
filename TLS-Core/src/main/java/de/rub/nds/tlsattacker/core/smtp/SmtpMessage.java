/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Base class for all SMTP messages.
 * SMTP messages are further divided into commands and replies.
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand
 * @see de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement
public abstract class SmtpMessage extends Message<SmtpContext> {

    /**
     * Returns the handler responsible for handling this type of message.
     * @param context the context of the SmtpLayer
     * @return a handler for this message
     * @see de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler
     */
    @Override
    public abstract SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext context);

    /**
     * Returns the parser responsible for parsing this type of message.
     * @param context the {@link SmtpContext}
     * @param stream an InputStream containing the message to be parsed
     * @return a parser for this message
     * @see de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser
     */
    @Override
    public abstract SmtpMessageParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream);

    /**
     * Returns the preparator responsible for preparing this type of message.
     * @param context the {@link SmtpContext}
     * @return a preparator for this message
     * @see de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator
     */
    @Override
    public abstract SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context);

    /**
     * Returns the serializer responsible for serializing this type of message.
     * @param context the {@link SmtpContext}
     * @return a serializer for this message
     * @see de.rub.nds.tlsattacker.core.smtp.serializer.SmtpMessageSerializer
     */
    @Override
    public abstract SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context);
}
