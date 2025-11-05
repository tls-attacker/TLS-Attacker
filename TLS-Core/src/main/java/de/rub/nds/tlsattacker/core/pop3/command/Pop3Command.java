/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3CommandHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3CommandSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class maps POP3 commands according to RFC1939. Pop3Commands consist of a single line with a
 * keyword and optional arguments separated by a single space. They are terminated with CRLF.
 */
@XmlRootElement
public class Pop3Command extends Pop3Message {

    final String keyword;
    String arguments;

    public Pop3Command(String keyword, String arguments) {
        this.keyword = keyword;
        this.arguments = arguments;
        this.commandType = Pop3CommandType.UNKNOWN;
    }
    public Pop3Command(Pop3CommandType commandType, String arguments) {
        this.commandType = commandType;
        this.keyword = commandType.getKeyword();
        this.arguments = arguments;
    }
    public Pop3Command() {
        // JAXB constructor
        this("", "");
    }

    @Override
    public Pop3CommandHandler<? extends Pop3Message> getHandler(Pop3Context pop3Context) {
        return new Pop3CommandHandler<>(pop3Context);
    }

    @Override
    public Pop3CommandParser<? extends Pop3Message> getParser(
            Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public Pop3CommandPreparator<? extends Pop3Message> getPreparator(Pop3Context context) {
        return new Pop3CommandPreparator<>(context.getChooser(), this);
    }

    @Override
    public Pop3CommandSerializer<? extends Pop3Message> getSerializer(Pop3Context context) {
        return new Pop3CommandSerializer<>(this, context);
    }

    @Override
    public String toShortString() {
        return "POP3_CMD";
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName()
                + " ("
                + keyword
                + (arguments != null ? " " + arguments : "")
                + ")";
    }

    public String getKeyword() {
        return keyword;
    }

    public String getArguments() {
        return arguments;
    }

    public void setArguments(String arguments) {
        this.arguments = arguments;
    }

    public String serialize() {
        final String SP = " ";
        final String CRLF = "\r\n";

        StringBuilder sb = new StringBuilder();

        if(this instanceof Pop3MessageNumber) {
            Pop3MessageNumber numberedMessage = (Pop3MessageNumber) this;
            if (numberedMessage.getMessageNumber() != null) {
                this.setArguments(numberedMessage.getMessageNumber().toString());
            }
        }

        boolean keywordExists = this.getKeyword() != null;
        boolean argumentsExist = this.getArguments() != null;

        if (keywordExists) {
            sb.append(this.getKeyword());
        }
        if (keywordExists && argumentsExist) {
            sb.append(SP);
        }
        if (argumentsExist) {
            sb.append(this.getArguments());
        }

        sb.append(CRLF);
        return sb.toString();
    }
}
