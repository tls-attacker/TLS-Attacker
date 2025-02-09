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

    private Pop3Command lastCommand = new Pop3InitialGreetingDummy();

    private boolean greetingReceived = false;

    public Pop3Context(Context context) {
        super(context);
    }

    public Pop3Reply getExpectedNextReplyType() {
        Pop3Command command = getLastCommand();
        return getExpectedReplyType(command);
    }

    public Pop3Command getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(Pop3Command lastCommand) {
        this.lastCommand = lastCommand;
    }

    public static Pop3Reply getExpectedReplyType(Pop3Command command) {
        if (command == null) {
            return null;
        }

        if (command instanceof Pop3USERCommand) {
            return new Pop3USERReply();
        } else if (command instanceof Pop3InitialGreetingDummy) {
            return new Pop3InitialGreeting();
        } else if (command instanceof Pop3PASSCommand) {
            return new Pop3PASSReply();
        } else if (command instanceof Pop3DELECommand) {
            return new Pop3DELEReply();
        } else if (command instanceof Pop3LISTCommand) {
            return new Pop3LISTReply();
        } else if (command instanceof Pop3NOOPCommand) {
            return new Pop3NOOPReply();
        } else if (command instanceof Pop3QUITCommand) {
            return new Pop3QUITReply();
        } else if (command instanceof Pop3RETRCommand) {
            return new Pop3RETRReply();
        } else if (command instanceof Pop3RSETCommand) {
            return new Pop3RSETReply();
        } else if (command instanceof Pop3STATCommand) {
            return new Pop3STATReply();
        } else if (command instanceof Pop3STLSCommand) {
            return new Pop3STLSReply();
        } else {
            throw new UnsupportedOperationException(
                    "No reply implemented for class in Pop3Context:" + command.getClass());
        }
    }

    public static Pop3Command getCommandTypeFromCommandName(String commandName) {
        switch (commandName) {
            case "USER":
                return new Pop3USERCommand();
            case "PASS":
                return new Pop3PASSCommand();
            case "DELE":
                return new Pop3DELECommand();
            case "LIST":
                return new Pop3LISTCommand();
            case "NOOP":
                return new Pop3NOOPCommand();
            case "QUIT":
                return new Pop3QUITCommand();
            case "RETR":
                return new Pop3RETRCommand();
            case "RSET":
                return new Pop3RSETCommand();
            case "STAT":
                return new Pop3STATCommand();
            case "STLS":
                return new Pop3STLSCommand();
            default:
                return new Pop3UnknownCommand();
        }
    }

    public boolean isGreetingReceived() {
        return greetingReceived;
    }

    public void setGreetingReceived(boolean greetingReceived) {
        this.greetingReceived = greetingReceived;
    }
}
