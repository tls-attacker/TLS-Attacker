/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.command.FtpInitialGreetingDummy;
import de.rub.nds.tlsattacker.core.ftp.reply.FtpReply;
import de.rub.nds.tlsattacker.core.state.Context;

/**
 * Runtime state for the FTP layer, used to drive the RFC 4217 STARTTLS ({@code AUTH TLS}) upgrade.
 */
public class FtpContext extends LayerContext {

    /**
     * Stores the last command that was sent to the server. When acting as a client, the reply type
     * is inferred from this command.
     */
    private FtpCommand lastCommand = new FtpInitialGreetingDummy();

    private boolean greetingReceived = false;

    public FtpContext(Context context) {
        super(context);
        context.setFtpContext(this);
    }

    public FtpReply getExpectedNextReplyType() {
        FtpCommand command = getLastCommand();
        return command.getCommandType().createReply();
    }

    public FtpCommand getLastCommand() {
        return lastCommand;
    }

    public void setLastCommand(FtpCommand lastCommand) {
        this.lastCommand = lastCommand;
    }

    public boolean isGreetingReceived() {
        return greetingReceived;
    }

    public void setGreetingReceived(boolean greetingReceived) {
        this.greetingReceived = greetingReceived;
    }
}
