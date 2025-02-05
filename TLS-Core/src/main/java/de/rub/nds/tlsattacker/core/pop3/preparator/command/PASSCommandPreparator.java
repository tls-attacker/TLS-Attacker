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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3PASSCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class PASSCommandPreparator extends Pop3CommandPreparator<Pop3PASSCommand> {
    public PASSCommandPreparator(Pop3Context context, Pop3PASSCommand passCommand) {
        super(context.getChooser(), passCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("PASS");
        if (this.getObject().getPassword() == null) {
            this.getObject().setPassword(chooser.getConfig().getDefaultPop3Password());
        }

        this.getObject().setArguments(this.getObject().getPassword());
    }
}
