/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SSL2ServerHelloPreparator extends ProtocolMessagePreparator<SSL2ServerHelloMessage> {

    public SSL2ServerHelloPreparator(Chooser chooser, SSL2ServerHelloMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareProtocolMessageContents() {
        throw new UnsupportedOperationException("Not supported Yet");
    }

    public void prepareAfterParse() {
    }

}
