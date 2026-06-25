/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.reply;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpInitialGreetingHandler;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Initial greeting (reply code 220) sent by the FTP server when a connection is established. Its
 * only use is to distinguish the initial greeting from truly unknown replies when receiving in
 * FtpLayer. It should never be included in a Workflow as a command.
 */
@XmlRootElement
public class FtpInitialGreeting extends FtpReply {

    public FtpInitialGreeting() {
        super(FtpCommandType.INITIAL_GREETING);
    }

    @Override
    public String toShortString() {
        return "FTP Initial Greeting";
    }

    @Override
    public FtpInitialGreetingHandler getHandler(Context context) {
        return new FtpInitialGreetingHandler(context.getFtpContext());
    }
}
