package de.rub.nds.tlsattacker.core.pop3.preparator;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class Pop3ReplyPreparator<ReplyT extends Pop3Reply> extends Pop3MessagePreparator<ReplyT> {

    protected final Pop3Context context;

    public Pop3ReplyPreparator(Chooser chooser, ReplyT message) {
        super(chooser, message);
        this.context = chooser.getContext().getPop3Context();
    }

    @Override
    public void prepare() {}

    @Override
    public Pop3Context getContext() {
        return context;
    }
}
