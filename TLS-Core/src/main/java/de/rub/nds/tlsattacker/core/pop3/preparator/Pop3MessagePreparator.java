package de.rub.nds.tlsattacker.core.pop3.preparator;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class Pop3MessagePreparator<MessageT extends Pop3Message> extends Preparator<MessageT> {

    protected final Pop3Context context;

    public Pop3MessagePreparator(Chooser chooser, MessageT message) {
        super(chooser, message);
        this.context = chooser.getContext().getPop3Context();
    }

    @Override
    public void prepare() {}

    public Pop3Context getContext() {
        return context;
    }
}
