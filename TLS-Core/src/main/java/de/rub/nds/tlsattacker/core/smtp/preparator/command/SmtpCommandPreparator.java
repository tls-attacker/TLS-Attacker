/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator.command;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpCommandPreparator<CommandT extends SmtpCommand>
        extends SmtpMessagePreparator<CommandT> {

    public SmtpCommandPreparator(Chooser chooser, CommandT command) {
        super(chooser, command);
    }

    @Override
    public void prepare() {}
}
