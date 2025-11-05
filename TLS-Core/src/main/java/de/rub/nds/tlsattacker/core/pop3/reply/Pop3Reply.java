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
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3ReplyHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3GenericReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3ReplyPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3ReplySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class models replies sent to pop3 Commands. Replies contain two possible status indicators
 * "+OK" or "-ERR" alongside a human-readable message corresponding to the status. This is true for
 * all specific pop3 replies, i.e. children of this class. Specific replies that contain additional
 * information are elaborated on in the respective classes themselves.
 */
@XmlRootElement
public class Pop3Reply extends Pop3Message {

    protected String statusIndicator;

    protected List<String> humanReadableMessages = new ArrayList<>();

    public Pop3Reply(Pop3CommandType type) {
        this(type, "");
    }

    public Pop3Reply(Pop3CommandType type, String statusIndicator) {
        this.commandType = type;
        this.humanReadableMessages = new ArrayList<>();
        this.statusIndicator = statusIndicator;
    }

    public Pop3Reply() {
        //Jaxb constructor
        this(Pop3CommandType.UNKNOWN, null);
    }

    public void setStatusIndicator(String statusIndicator) {
        this.statusIndicator = statusIndicator;
    }

    public String getStatusIndicator() {
        return statusIndicator;
    }

    public boolean statusIsPositive() {
        return this.statusIndicator.equals("+OK");
    }

    public void setHumanReadableMessage(String message) {
        this.humanReadableMessages = new ArrayList<>(List.of(message));
    }

    public void setHumanReadableMessages(List<String> humanReadableMessage) {
        this.humanReadableMessages = humanReadableMessage;
    }

    public String getHumanReadableMessage() {
        if (this.humanReadableMessages.isEmpty()) {
            return "";
        } else {
            return this.humanReadableMessages.get(0);
        }
    }

    @Override
    public String toShortString() {
        return "POP3_REPLY";
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getStatusIndicator())
                .append(" ")
                .append(this.getCommandType().getKeyword())
                .append("Reply");
        return sb.toString();
    }

    @Override
    public Pop3ReplyHandler<? extends Pop3Reply> getHandler(Pop3Context pop3Context) {
        return new Pop3ReplyHandler<>(pop3Context);
    }

    @Override
    public Pop3ReplyParser<? extends Pop3Reply> getParser(Pop3Context context, InputStream stream) {
        return new Pop3GenericReplyParser<>(stream);
    }

    @Override
    public Pop3ReplyPreparator<? extends Pop3Reply> getPreparator(Pop3Context context) {
        return new Pop3ReplyPreparator<>(context.getChooser(), this);
    }

    @Override
    public Pop3ReplySerializer<? extends Pop3Reply> getSerializer(Pop3Context context) {
        return new Pop3ReplySerializer<>(this, context);
    }

    public String serialize() {
        char SP = ' ';
        String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();
        sb.append(this.statusIndicator != null ? this.statusIndicator : "");
        if (!this.humanReadableMessages.isEmpty()) {
            sb.append(SP);
            sb.append(this.humanReadableMessages.get(0));
        }
        sb.append(CRLF);
        for (int i = 1; i < this.humanReadableMessages.size(); i++) {
            sb.append(this.humanReadableMessages.get(i));
            sb.append(CRLF);
        }
        // End Multiline reply
        if (this.humanReadableMessages.size() > 1) {
            sb.append(".");
            sb.append(CRLF);
        }
        return sb.toString();
    }
}
