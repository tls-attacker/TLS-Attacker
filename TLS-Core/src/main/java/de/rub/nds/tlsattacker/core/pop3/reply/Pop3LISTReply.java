/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3LISTReplyParser;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * The POP3 LIST reply contains information regarding the messages in the mail drop. This
 * information consists of the message numbers (identifiers) and sizes of the messages.
 */
@XmlRootElement
public class Pop3LISTReply extends Pop3Reply {
    private List<Integer> messageNumbers = new ArrayList<>();
    private List<Integer> messageSizes = new ArrayList<>();

    public Pop3LISTReply() {
        super(Pop3CommandType.LIST);
    }

    @Override
    public Pop3LISTReplyParser getParser(Pop3Context context, InputStream stream) {
        return new Pop3LISTReplyParser(context, stream);
    }

    public void setMessageNumbers(List<Integer> messageNumbers) {
        this.messageNumbers = messageNumbers;
    }

    public List<Integer> getMessageNumbers() {
        return messageNumbers;
    }

    public void addMessageNumber(Integer messageNumber) {
        this.messageNumbers.add(messageNumber);
    }

    public void addMessageSize(Integer messageSize) {
        this.messageSizes.add(messageSize);
    }

    public void setMessageSizes(List<Integer> messageSizes) {
        this.messageSizes = messageSizes;
    }

    public List<Integer> getMessageSizes() {
        return messageSizes;
    }

    @Override
    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";
        String humanReadableMessage = this.getHumanReadableMessage();

        StringBuilder sb = new StringBuilder();
        sb.append(this.statusIndicator);
        if (!humanReadableMessage.isEmpty()) {
            sb.append(SP);
            sb.append(humanReadableMessage);
        }

        sb.append(CRLF);
        for (int i = 0; i < messageNumbers.size(); i++) {
            sb.append(messageNumbers.get(i));
            sb.append(SP);
            sb.append(messageSizes.get(i));
            sb.append(CRLF);
        }
        if (!messageNumbers.isEmpty()) {
            sb.append(".");
            sb.append(CRLF);
        }

        return sb.toString();
    }
}
