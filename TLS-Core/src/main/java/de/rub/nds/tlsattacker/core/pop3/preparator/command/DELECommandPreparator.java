package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.DELECommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class DELECommandPreparator extends Pop3CommandPreparator<DELECommand> {
    public DELECommandPreparator(SmtpContext context, DELECommand deleCommand) {
        super(context.getChooser(), deleCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("DELE");
        if (this.getObject().getMessageNumber() == null) {
            this.getObject().setMessageNumber(chooser.getConfig().getDefaultPop3MessageNumber());
        } else {
            this.getObject().setArguments(String.valueOf(this.getObject().getMessageNumber()));
        }
    }
}
