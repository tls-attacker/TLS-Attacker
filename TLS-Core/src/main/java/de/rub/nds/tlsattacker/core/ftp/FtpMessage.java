/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp;

import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpMessageHandler;
import de.rub.nds.tlsattacker.core.ftp.parser.FtpMessageParser;
import de.rub.nds.tlsattacker.core.ftp.preparator.FtpMessagePreparator;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.InputStream;

/**
 * Base class for all FTP messages (commands and replies) used during the RFC 4217
 * control-connection STARTTLS upgrade ({@code AUTH TLS}).
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({FtpCommand.class, FtpReply.class})
public abstract class FtpMessage extends Message {

    protected FtpCommandType commandType = FtpCommandType.UNKNOWN;

    /**
     * Returns the handler for this type of message.
     *
     * @param context the context of the ftp layer
     * @return a handler for this message
     */
    @Override
    public abstract FtpMessageHandler<? extends FtpMessage> getHandler(Context context);

    /**
     * Returns the parser responsible for parsing this type of message.
     *
     * @param context the context of the ftp layer
     * @param stream the InputStream which contains the message to be parsed
     * @return a parser for this message
     */
    @Override
    public abstract FtpMessageParser<? extends FtpMessage> getParser(
            Context context, InputStream stream);

    /**
     * Returns the preparator for this type of message.
     *
     * @param context the context of the ftp layer
     * @return a preparator for this message
     */
    @Override
    public abstract FtpMessagePreparator<? extends FtpMessage> getPreparator(Context context);

    /**
     * Returns the serializer for this type of message.
     *
     * @param context the context of the ftp layer
     * @return a serializer for this message
     */
    @Override
    public abstract FtpMessageSerializer<? extends FtpMessage> getSerializer(Context context);

    public FtpCommandType getCommandType() {
        return commandType;
    }
}
