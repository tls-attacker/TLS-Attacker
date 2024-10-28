/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.preparator;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class Pop3CommandPreparator<CommandT extends Pop3Command>
        extends Pop3MessagePreparator<CommandT> {
    public Pop3CommandPreparator(Chooser chooser, CommandT message) {
        super(chooser, message);
    }

    @Override
    public void prepare() {}
}
