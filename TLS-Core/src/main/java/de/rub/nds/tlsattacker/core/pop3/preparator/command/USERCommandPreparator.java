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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3USERCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class USERCommandPreparator extends Pop3CommandPreparator<Pop3USERCommand> {
    public USERCommandPreparator(Pop3Context context, Pop3USERCommand userCommand) {
        super(context.getChooser(), userCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("USER");
        if (this.getObject().getUsername() == null) {
            this.getObject().setUsername(chooser.getConfig().getDefaultPop3Username());
        }

        this.getObject().setArguments(this.getObject().getUsername());
    }
}
