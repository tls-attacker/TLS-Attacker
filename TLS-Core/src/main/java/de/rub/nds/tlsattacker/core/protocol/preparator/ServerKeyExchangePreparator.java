/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.TlsSignatureUtil;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * @param <T> The ServerKeyExchangeMessage that should be prepared
 */
public abstract class ServerKeyExchangePreparator<T extends ServerKeyExchangeMessage>
        extends HandshakeMessagePreparator<T> {

    public ServerKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    protected byte[] generateSignature(SignatureAndHashAlgorithm algorithm, byte[] toBeHashedAndSigned) {
        TlsSignatureUtil util = new TlsSignatureUtil();
        util.computeSignature(chooser, algorithm, toBeHashedAndSigned, message.getSignatureComputations(algorithm.getSignatureAlgorithm()));
        return message.getSignatureComputations(algorithm.getSignatureAlgorithm()).getSignatureBytes().getValue();
    }
}
