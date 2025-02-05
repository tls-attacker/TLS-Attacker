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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3LISTCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class LISTCommandPreparator extends Pop3CommandPreparator<Pop3LISTCommand> {
    public LISTCommandPreparator(Pop3Context context, Pop3LISTCommand listCommand) {
        super(context.getChooser(), listCommand);
    }

    @Override
    public void prepare() {
        this.getObject()
                .setKeyword(
                        "LIST"); // list may have no arguments, hence no default argument necessary
        if (this.getObject().hasMessageNumber()) {
            this.getObject().setArguments(String.valueOf(this.getObject().getMessageNumber()));
        }
    }
}
