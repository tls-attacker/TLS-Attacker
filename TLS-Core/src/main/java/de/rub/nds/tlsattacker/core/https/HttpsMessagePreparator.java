/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class HttpsMessagePreparator<T extends HttpsMessage> extends Preparator<T> {

    protected final T message;

    public HttpsMessagePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public final void prepare() {
        prepareHttpsMessageContents();
    }

    protected abstract void prepareHttpsMessageContents();

}
