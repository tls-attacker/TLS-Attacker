/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.preparator;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class Pop3ReplyPreparator<ReplyT extends Pop3Reply> extends Pop3MessagePreparator<ReplyT> {

    protected final Pop3Context context;

    public Pop3ReplyPreparator(Chooser chooser, ReplyT message) {
        super(chooser, message);
        this.context = chooser.getContext().getPop3Context();
    }

    @Override
    public Pop3Context getContext() {
        return context;
    }
}
