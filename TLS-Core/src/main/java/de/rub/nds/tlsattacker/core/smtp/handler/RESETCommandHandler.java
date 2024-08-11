package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRESETCommand;

/**
 * Handles the execution of the reset command by clearing all buffers.
 */

public class RESETCommandHandler extends SmtpCommandHandler<SmtpRESETCommand> {
    public RESETCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpRESETCommand command) {
        this.getContext().clearBuffers();
    }
}
