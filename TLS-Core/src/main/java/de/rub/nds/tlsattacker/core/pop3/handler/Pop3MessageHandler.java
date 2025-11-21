/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.handler;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;

public abstract class Pop3MessageHandler<MessageT extends Pop3Message> extends Handler<MessageT> {

    protected final Pop3Context context;

    public Pop3MessageHandler(Pop3Context context) {
        this.context = context;
    }

    public void adjustContext(MessageT container) {}

    public Pop3Context getContext() {
        return context;
    }
}
