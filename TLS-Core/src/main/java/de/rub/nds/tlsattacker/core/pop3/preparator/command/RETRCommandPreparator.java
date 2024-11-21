package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.DELECommand;
import de.rub.nds.tlsattacker.core.pop3.command.RETRCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class RETRCommandPreparator extends Pop3CommandPreparator<RETRCommand> {
    public RETRCommandPreparator(Pop3Context context, RETRCommand retrCommand) {
        super(context.getChooser(), retrCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("RETR");
        if (this.getObject().getMessageNumber() == null) {
            this.getObject().setMessageNumber(chooser.getConfig().getDefaultPop3MessageNumber());
        }

        this.getObject().setArguments(String.valueOf(this.getObject().getMessageNumber()));
    }
}
