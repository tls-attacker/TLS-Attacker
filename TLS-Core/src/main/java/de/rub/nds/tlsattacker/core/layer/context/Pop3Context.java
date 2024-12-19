/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.pop3.command.*;
import de.rub.nds.tlsattacker.core.pop3.reply.*;
import de.rub.nds.tlsattacker.core.state.Context;

public class Pop3Context extends LayerContext {

    private Pop3Command lastCommand = null;

    public Pop3Context(Context context) {
        super(context);
    }

    public Pop3Command getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(Pop3Command lastCommand) {
        this.lastCommand = lastCommand;
    }

    public Pop3Reply getExpectedNextReplyType() {
        Pop3Command command = getLastCommand();
        return getExpectedReplyType(command);
    }

    public static Pop3Reply getExpectedReplyType(Pop3Command command) {
        if (command == null) {
            return null;
        }

        if (command instanceof USERCommand) {
            return new Pop3USERReply();
        } else if (command instanceof PASSCommand) {
            return new Pop3PASSReply();
        } else if (command instanceof DELECommand) {
            return new Pop3DELReply();
        } else if (command instanceof LISTCommand) {
            return new Pop3LISTReply();
        } else if (command instanceof NOOPCommand) {
            return new Pop3NOOPReply();
        } else if (command instanceof QUITCommand) {
            return new Pop3QUITReply();
        } else if (command instanceof RETRCommand) {
            return new Pop3RETRReply();
        } else if (command instanceof RSETCommand) {
            return new Pop3RSETReply();
        } else if (command instanceof STATCommand) {
            return new Pop3STATReply();
        } else {
            throw new UnsupportedOperationException(
                    "No reply implemented for class in Pop3Context:" + command.getClass());
        }
    }
}
