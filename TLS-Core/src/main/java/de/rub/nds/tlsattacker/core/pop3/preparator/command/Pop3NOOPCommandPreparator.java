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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class Pop3NOOPCommandPreparator extends Pop3CommandPreparator<Pop3NOOPCommand> {
    public Pop3NOOPCommandPreparator(Pop3Context context, Pop3NOOPCommand noopCommand) {
        super(context.getChooser(), noopCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("NOOP");
    }
}
