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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.LISTCommandPreparator;
import java.io.InputStream;

/**
 * With no parameters, this command lists all messages with corresponding message information. With
 * a message number specified, it only lists the information of one message.
 */
public class LISTCommand extends Pop3Command implements MessageNumber {

    private Integer messageNumber; // optional, TODO: decide whether having this as a string is more
    // convenient
    private boolean hasMessageNumber = false;
    private static final String commandName = "LIST";

    public LISTCommand() {
        super(commandName, null);
    }

    public LISTCommand(int messageNumber) {
        super(commandName, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
        this.hasMessageNumber = true;
    }

    public void setMessageNumber(Integer messageNumber) {
        this.messageNumber = messageNumber;
        this.hasMessageNumber = true;
    }

    public Integer getMessageNumber() {
        return this.messageNumber;
    }

    public boolean hasMessageNumber() {
        return hasMessageNumber;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3CommandParser<LISTCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public LISTCommandPreparator getPreparator(Pop3Context context) {
        return new LISTCommandPreparator(context, this);
    }
}
