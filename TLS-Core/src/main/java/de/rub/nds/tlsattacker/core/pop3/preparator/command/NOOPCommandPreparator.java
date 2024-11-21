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
import de.rub.nds.tlsattacker.core.pop3.command.NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class NOOPCommandPreparator extends Pop3CommandPreparator<NOOPCommand> {
    public NOOPCommandPreparator(Pop3Context context, NOOPCommand noopCommand) {
        super(context.getChooser(), noopCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("NOOP");
    }
}
