/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

public class EmptyClientKeyExchangePreparator<T extends EmptyClientKeyExchangeMessage> extends ClientKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected byte[] random;
    protected final T msg;

    public EmptyClientKeyExchangePreparator(Chooser chooser, T msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing EmptyClientKeyExchangeMessage");
        prepareAfterParse(true);
    }

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        random = msg.getComputations().getClientServerRandom().getValue();
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
    }


}
