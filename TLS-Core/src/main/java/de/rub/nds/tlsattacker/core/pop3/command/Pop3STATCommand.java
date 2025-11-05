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
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * The POP3 STAT command is used to retrieve two stats regarding the mailbox: 1. The number of
 * messages in the mailbox. 2. The total size taken up by all messages (in octets). The STAT command
 * does not have any parameters.
 */
@XmlRootElement
public class Pop3STATCommand extends Pop3Command {
    public Pop3STATCommand() {
        super(Pop3CommandType.STAT, null);
    }
}
