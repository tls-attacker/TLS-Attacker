package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.PASSCommand;
import de.rub.nds.tlsattacker.core.pop3.command.USERCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class PASSCommandPreparator extends Pop3CommandPreparator<PASSCommand> {
    public PASSCommandPreparator(SmtpContext context, PASSCommand passCommand) {
        super(context.getChooser(), passCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("PASS");
        if (this.getObject().getPassword() == null) {
            this.getObject().setPassword(chooser.getConfig().getDefaultPop3Password());
        } else {
            this.getObject().setArguments(this.getObject().getPassword());
        }
    }
}
