/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3LISTCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * When no parameters are specified, this command lists all messages with corresponding message
 * information. With a message number specified, it only lists the information of one message.
 */
@XmlRootElement
public class Pop3LISTCommand extends Pop3Command implements Pop3MessageNumber {

    private Integer messageNumber; // optional, see boolean variable hasMessageNumber
    private boolean hasMessageNumber = false;

    public Pop3LISTCommand() {
        super(Pop3CommandType.LIST, null);
    }

    public Pop3LISTCommand(int messageNumber) {
        super(Pop3CommandType.LIST, String.valueOf(messageNumber));
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
    public Pop3LISTCommandPreparator getPreparator(Context context) {
        return new Pop3LISTCommandPreparator(context.getPop3Context(), this);
    }
}
