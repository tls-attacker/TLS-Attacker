/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.pop3.Pop3MappingUtil;
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
        return Pop3MappingUtil.getMatchingReply(command);
    }

    public Pop3Command getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(Pop3Command lastCommand) {
        this.lastCommand = lastCommand;
    }

    public boolean isGreetingReceived() {
        return greetingReceived;
    }

    public void setGreetingReceived(boolean greetingReceived) {
        this.greetingReceived = greetingReceived;
    }
}
