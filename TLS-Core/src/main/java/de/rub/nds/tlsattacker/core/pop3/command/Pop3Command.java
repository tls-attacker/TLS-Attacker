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

    String keyword;

    String arguments;

    public Pop3Command(String keyword, String arguments) {
        super();
        this.keyword = keyword;
        this.arguments = arguments;
    }

    public Pop3Command(String keyword) {
        this.keyword = keyword;
    }

    public Pop3Command() {}

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

    public String getKeyword() {
        return keyword;
    }

    public void setKeyword(String keyword) {
        this.keyword = keyword;
    }

    public String getArguments() {
        return arguments;
    }

    public void setArguments(String arguments) {
        this.arguments = arguments;
    }

    // To be overwritten by subclass:
    public String getCommandName() {
        return "";
    }
}
