/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;

public class SSL2ClientMasterKeyHandler extends ProtocolMessageHandler<SSL2ClientMasterKeyMessage> {

    public SSL2ClientMasterKeyHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(SSL2ClientMasterKeyMessage message) {
        byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
        tlsContext.setPreMasterSecret(premasterSecret);
        tlsContext.setClearKey(message.getClearKeyData().getValue());
        if (tlsContext.getChooser().getSSL2CipherSuite().getBlockSize() != 0) {
            tlsContext.setSSL2Iv(message.getKeyArgData().getValue());
        }
    }
}
