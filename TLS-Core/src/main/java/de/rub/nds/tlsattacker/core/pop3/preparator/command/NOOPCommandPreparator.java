package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.LISTCommand;
import de.rub.nds.tlsattacker.core.pop3.command.NOOPCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class NOOPCommandPreparator extends Pop3CommandPreparator<NOOPCommand> {
    public NOOPCommandPreparator(Pop3Context context, NOOPCommand noopCommand) {
        super(context.getChooser(), noopCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("NOOP");
    }
}
