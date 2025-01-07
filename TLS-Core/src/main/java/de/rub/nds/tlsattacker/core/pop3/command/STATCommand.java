/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

// TODO: decide whether to change naming convention, e.g. Pop3StatCommand is less readable imo

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.STATCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

/**
 * The POP3 STAT command is used to retrieve two stats regarding the mailbox:
 *
 * <ol>
 *   <li>The number of messages in the mailbox.
 *   <li>The total size taken up by all messages (in octets).
 * </ol>
 *
 * The STAT command does not have any parameters.
 */

@XmlRootElement
public class STATCommand extends Pop3Command {
    private static final String commandName = "STAT";

    public STATCommand() {
        super(commandName, null);
    }

    @Override
    public Pop3CommandParser<STATCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public STATCommandPreparator getPreparator(Pop3Context context) {
        return new STATCommandPreparator(context, this);
    }

    @Override
    public String getCommandName() {
        return commandName;
    }
}
