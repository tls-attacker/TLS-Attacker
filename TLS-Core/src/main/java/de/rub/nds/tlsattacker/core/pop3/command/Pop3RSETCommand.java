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
import jakarta.xml.bind.annotation.XmlRootElement;

/** POP3 Servers use this command to revert deletion of messages. */
@XmlRootElement
public class Pop3RSETCommand extends Pop3Command {
    public Pop3RSETCommand() {
        super(Pop3CommandType.RSET, null);
    }
}
