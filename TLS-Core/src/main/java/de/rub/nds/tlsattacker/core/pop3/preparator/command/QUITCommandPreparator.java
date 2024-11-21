package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.command.QUITCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class QUITCommandPreparator extends Pop3CommandPreparator<QUITCommand> {
    public QUITCommandPreparator(Pop3Context context, QUITCommand quitCommand) {
        super(context.getChooser(), quitCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("QUIT");
    }
}
