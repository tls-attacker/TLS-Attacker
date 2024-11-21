package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.DELECommand;
import de.rub.nds.tlsattacker.core.pop3.command.USERCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class USERCommandPreparator extends Pop3CommandPreparator<USERCommand> {
    public USERCommandPreparator(SmtpContext context, USERCommand userCommand) {
        super(context.getChooser(), userCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("USER");
        if (this.getObject().getUsername() == null) {
            this.getObject().setUsername(chooser.getConfig().getDefaultPop3Username());
        } else {
            this.getObject().setArguments(this.getObject().getUsername());
        }
    }
}
