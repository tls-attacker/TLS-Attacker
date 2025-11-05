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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3DELECommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** The Pop3DELECommand deletes a message with the specified messageNumber. */
@XmlRootElement
public class Pop3DELECommand extends Pop3Command implements Pop3MessageNumber {
    private Integer messageNumber;

    public Pop3DELECommand() {
        super(Pop3CommandType.DELE, null);
    }
    public Pop3DELECommand(int messageNumber) {
        super(Pop3CommandType.DELE, String.valueOf(messageNumber));
        this.messageNumber = messageNumber;
    }

    public Integer getMessageNumber() {
        return messageNumber;
    }

    public void setMessageNumber(Integer messageNumber) {
        this.messageNumber = messageNumber;
    }

    @Override
    public Pop3DELECommandPreparator getPreparator(Pop3Context context) {
        return new Pop3DELECommandPreparator(context, this);
    }
}
