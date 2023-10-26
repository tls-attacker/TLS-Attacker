/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangeHandler<T extends ECDHClientKeyExchangeMessage<?>>
        extends ClientKeyExchangeHandler<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(T message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        adjustClientPublicKey(message);
        spawnNewSession();
    }

    private void adjustClientPublicKey(T message) {
        byte[] serializedPoint = message.getPublicKey().getValue();
        NamedGroup usedGroup = tlsContext.getChooser().getSelectedNamedGroup();
        LOGGER.debug("Adjusting EC Point");
        Point publicKey = PointFormatter.formatFromByteArray(usedGroup, serializedPoint);
        tlsContext.setClientEcPublicKey(publicKey);
    }
}
