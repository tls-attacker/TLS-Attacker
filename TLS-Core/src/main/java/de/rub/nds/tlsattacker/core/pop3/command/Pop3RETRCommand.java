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
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3RETRCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;

/** The Pop3RETRCommand retrieves a message with the specified messageNumber. */
@XmlRootElement
public class Pop3RETRCommand extends Pop3Command implements Pop3MessageNumber {

    private Integer messageNumber;
    private static final String commandName = "RETR";

    public Pop3RETRCommand() {
        super(Pop3CommandType.RETR, null);
    }

    public Pop3RETRCommand(int messageNumber) {
        super(Pop3CommandType.RETR, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public Integer getMessageNumber() {
        return messageNumber;
    }

    public void setMessageNumber(Integer messageNumber) {
        this.messageNumber = messageNumber;
    }

    @Override
    public Pop3RETRCommandPreparator getPreparator(Context context) {
        return new Pop3RETRCommandPreparator(context.getPop3Context(), this);
    }
}
