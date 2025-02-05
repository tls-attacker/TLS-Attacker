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
import de.rub.nds.tlsattacker.core.pop3.preparator.command.RETRCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** The Pop3RETRCommand retrieves the message with the specified messageNumber. */
@XmlRootElement
public class Pop3RETRCommand extends Pop3Command implements MessageNumber {

    private Integer messageNumber;
    private static final String commandName = "RETR";

    public Pop3RETRCommand() {
        super(commandName);
    }

    public Pop3RETRCommand(int messageNumber) {
        super(commandName, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public Integer getMessageNumber() {
        return messageNumber;
    }

    public void setMessageNumber(Integer messageNumber) {
        this.messageNumber = messageNumber;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3CommandParser<Pop3RETRCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public RETRCommandPreparator getPreparator(Pop3Context context) {
        return new RETRCommandPreparator(context, this);
    }
}
