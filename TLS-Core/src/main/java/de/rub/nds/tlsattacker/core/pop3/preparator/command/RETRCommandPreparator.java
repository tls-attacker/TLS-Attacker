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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3RETRCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class RETRCommandPreparator extends Pop3CommandPreparator<Pop3RETRCommand> {
    public RETRCommandPreparator(Pop3Context context, Pop3RETRCommand retrCommand) {
        super(context.getChooser(), retrCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("RETR");
        if (this.getObject().getMessageNumber() == null) {
            this.getObject().setMessageNumber(chooser.getConfig().getDefaultPop3MessageNumber());
        }

        this.getObject().setArguments(String.valueOf(this.getObject().getMessageNumber()));
    }
}
