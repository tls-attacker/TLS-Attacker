/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SSL2ServerHelloPreparator extends HandshakeMessagePreparator<SSL2ServerHelloMessage> {

    public SSL2ServerHelloPreparator(Chooser chooser, SSL2ServerHelloMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        throw new UnsupportedOperationException("Not supported Yet");
    }

    public void prepareAfterParse() {
    }

}
