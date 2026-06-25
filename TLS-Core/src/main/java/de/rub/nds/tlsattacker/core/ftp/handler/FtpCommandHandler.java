/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.handler;

import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;

public class FtpCommandHandler<CommandT extends FtpCommand> extends FtpMessageHandler<CommandT> {

    public FtpCommandHandler(FtpContext context) {
        super(context);
    }

    @Override
    public void adjustContext(CommandT ftpCommand) {
        this.context.setLastCommand(ftpCommand);
        adjustContextSpecific(ftpCommand);
    }

    /**
     * Adjusts the {@link FtpContext} with information from the command. Subclasses should override
     * this method to update the {@link FtpContext} accordingly.
     *
     * @param ftpCommand the command to process
     */
    public void adjustContextSpecific(CommandT ftpCommand) {}
}
