/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3MessageHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3MessagePreparator;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3CommandSerializer;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3ReplySerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.InputStream;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({Pop3Command.class, Pop3Reply.class})
public abstract class Pop3Message extends Message {

    protected Pop3CommandType commandType = Pop3CommandType.UNKNOWN;

    /**
     * Returns the handler for this type of message.
     *
     * @param pop3Context the context of the pop3 layer
     * @return a handler for this message
     */
    @Override
    public abstract Pop3MessageHandler<? extends Pop3Message> getHandler(Context pop3Context);

    /**
     * Returns the parser responsible for parsing this type of message.
     *
     * @param context the context of the pop3 layer
     * @param stream the InputStream which contains the message to be parsed
     * @return a parser for this message
     */
    @Override
    public abstract Pop3MessageParser<? extends Pop3Message> getParser(
            Context context, InputStream stream);

    /**
     * Returns the preparator for this type of message.
     *
     * @param context the context of the pop3 layer
     * @return a preparator for this message
     */
    @Override
    public abstract Pop3MessagePreparator<? extends Pop3Message> getPreparator(Context context);

    /**
     * Returns the serializer for this type of message. In practice, this will only be a {@link
     * Pop3CommandSerializer} or {@link Pop3ReplySerializer} which in turn wrap each classes {@code
     * serializeBytes} function. This is a matter of style and convenience, different from our
     * original implementation for SMTP.
     *
     * @param context the context of the pop3 layer
     * @return a serializer for this message
     */
    @Override
    public abstract Pop3MessageSerializer<? extends Pop3Message> getSerializer(Context context);

    public Pop3CommandType getCommandType() {
        return commandType;
    }
}
