/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.command.STLSCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class STLSCommandPreparator extends Pop3CommandPreparator<STLSCommand> {
    public STLSCommandPreparator(Pop3Context context, STLSCommand starttlsCommand) {
        super(context.getChooser(), starttlsCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("STLS");
    }
}
