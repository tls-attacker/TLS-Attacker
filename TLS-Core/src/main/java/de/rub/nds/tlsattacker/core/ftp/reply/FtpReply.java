/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.reply;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpReplyHandler;
import de.rub.nds.tlsattacker.core.ftp.parser.reply.FtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.ftp.parser.reply.FtpReplyParser;
import de.rub.nds.tlsattacker.core.ftp.preparator.FtpReplyPreparator;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpReplySerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Base class for modelling replies to FTP commands. A reply consists of a three-digit status code
 * and a human-readable message. Multiline replies repeat the code with a dash ("{@code NNN-}") on
 * every line except the last, which uses a space ("{@code NNN }"). For example: <br>
 * S: 234 AUTH command ok. Initializing TLS Connection.
 */
@XmlRootElement
public class FtpReply extends FtpMessage {

    protected Integer replyCode = 0; // some invalid value to indicate that it was not set
    protected List<String> humanReadableMessages = new ArrayList<>();

    public FtpReply(FtpCommandType type) {
        this.commandType = type;
        this.humanReadableMessages = new ArrayList<>();
    }

    public FtpReply(FtpCommandType type, Integer replyCode) {
        this(type);
        this.replyCode = replyCode;
    }

    public FtpReply() {
        // JAXB constructor
        this(FtpCommandType.UNKNOWN);
    }

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
        if (this.humanReadableMessages.isEmpty()) {
            return "";
        }
        return this.humanReadableMessages.get(0);
    }

    public boolean isMultiline() {
        return this.humanReadableMessages.size() > 1;
    }

    public void setReplyCode(Integer replyCode) {
        this.replyCode = replyCode;
    }

    public int getReplyCode() {
        return replyCode;
    }

    @Override
    public FtpReplyHandler<? extends FtpReply> getHandler(Context context) {
        return new FtpReplyHandler<>(context.getFtpContext());
    }

    @Override
    public FtpReplyParser<? extends FtpReply> getParser(Context context, InputStream stream) {
        return new FtpGenericReplyParser<>(stream);
    }

    @Override
    public FtpReplyPreparator<? extends FtpReply> getPreparator(Context context) {
        return new FtpReplyPreparator<>(context.getChooser(), this);
    }

    @Override
    public FtpReplySerializer<? extends FtpReply> getSerializer(Context context) {
        return new FtpReplySerializer<>(this, context.getFtpContext());
    }

    @Override
    public String toShortString() {
        return "FTP_REPLY";
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getReplyCode())
                .append(" ")
                .append(this.getCommandType().getKeyword())
                .append("Reply");
        return sb.toString();
    }

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
        if (!this.humanReadableMessages.isEmpty()) {
            sb.append(SP);
            sb.append(this.humanReadableMessages.get(this.humanReadableMessages.size() - 1));
        }
        sb.append(CRLF);

        return sb.toString();
    }
}
