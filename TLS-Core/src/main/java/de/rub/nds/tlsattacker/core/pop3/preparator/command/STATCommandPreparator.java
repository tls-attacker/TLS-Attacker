package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.QUITCommand;
import de.rub.nds.tlsattacker.core.pop3.command.STATCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class STATCommandPreparator extends Pop3CommandPreparator<STATCommand> {
    public STATCommandPreparator(SmtpContext context, STATCommand statCommand) {
        super(context.getChooser(), statCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("STAT");
    }
}
