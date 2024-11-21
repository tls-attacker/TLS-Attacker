package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.QUITCommand;
import de.rub.nds.tlsattacker.core.pop3.command.RSETCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class RSETCommandPreparator extends Pop3CommandPreparator<RSETCommand> {
    public RSETCommandPreparator(SmtpContext context, RSETCommand rsetCommand) {
        super(context.getChooser(), rsetCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("RSET");
    }
}
