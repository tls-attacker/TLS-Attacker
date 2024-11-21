package de.rub.nds.tlsattacker.core.pop3.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.pop3.command.DELECommand;
import de.rub.nds.tlsattacker.core.pop3.command.LISTCommand;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;

public class LISTCommandPreparator extends Pop3CommandPreparator<LISTCommand> {
    public LISTCommandPreparator(SmtpContext context, LISTCommand listCommand) {
        super(context.getChooser(), listCommand);
    }

    @Override
    public void prepare() {
        this.getObject().setKeyword("LIST"); // list may have no arguments, hence no default argument necessary
        if (this.getObject().hasMessageNumber()) {
            this.getObject().setArguments(String.valueOf(this.getObject().getMessageNumber()));
        }
    }
}
