package de.rub.nds.tlsattacker.core.pop3.preparator;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class Pop3CommandPreparator<CommandT extends Pop3Command> extends Pop3MessagePreparator<CommandT> {
    public Pop3CommandPreparator(Chooser chooser, CommandT message) {
        super(chooser, message);
    }

    @Override
    public void prepare() {}
}
