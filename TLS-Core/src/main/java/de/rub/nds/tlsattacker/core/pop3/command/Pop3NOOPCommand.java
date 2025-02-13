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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3NOOPCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement
public class Pop3NOOPCommand extends Pop3Command {

    private static final String commandName = "NOOP";

    public Pop3NOOPCommand() {
        super(commandName, null);
    }

    @Override
    public Pop3CommandParser<Pop3NOOPCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public Pop3NOOPCommandPreparator getPreparator(Pop3Context context) {
        return new Pop3NOOPCommandPreparator(context, this);
    }

    @Override
    public String getCommandName() {
        return commandName;
    }
}
