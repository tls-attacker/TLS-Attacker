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
 * Class modelling replies to Pop3 Commands. two possible status indicators: +OK or -ERR together
 * with a human-readable message. C: QUIT S: +OK POP3 server signing off
 */
@XmlRootElement
public class Pop3Reply extends Pop3Message {

    protected String statusIndicator;

    protected List<String> humanReadableMessage = new ArrayList<>();

    public Pop3Reply() {
        this.humanReadableMessage = new ArrayList<>();
    }

    public Pop3Reply(String statusIndicator) {
        super();
        this.statusIndicator = statusIndicator;
    }

    public void setStatusIndicator(String statusIndicator) {
        this.statusIndicator = statusIndicator;
    }

    public String getStatusIndicator() {
        return statusIndicator;
    }

    public void setHumanReadableMessage(String message) {
        this.humanReadableMessage = new ArrayList<>(List.of(message));
    }

    public void setHumanReadableMessages(List<String> humanReadableMessage) {
        this.humanReadableMessage = humanReadableMessage;
    }

    public String getHumanReadableMessage() {
        if (this.humanReadableMessage.isEmpty()) return "";
        else return this.humanReadableMessage.get(0);
    }

    @Override
    public String toShortString() {
        return "POP3_REPLY";
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
        if (!this.humanReadableMessage.isEmpty()) {
            sb.append(SP);
            sb.append(this.humanReadableMessage.get(0));
        }
        sb.append(CRLF);
        for (int i = 1; i < this.humanReadableMessage.size(); i++) {
            sb.append(this.humanReadableMessage.get(i));
            sb.append(CRLF);
        }
        // End Multiline reply
        if (this.humanReadableMessage.size() > 1) {
            sb.append(".");
            sb.append(CRLF);
        }
        return sb.toString();
    }
}
