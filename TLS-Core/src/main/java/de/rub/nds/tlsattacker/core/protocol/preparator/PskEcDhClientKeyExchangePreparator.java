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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;

public class PskEcDhClientKeyExchangePreparator extends
        ECDHClientKeyExchangePreparator<PskEcDhClientKeyExchangeMessage> {

    private ByteArrayOutputStream outputStream;
    private final PskEcDhClientKeyExchangeMessage msg;

    public PskEcDhClientKeyExchangePreparator(Chooser chooser, PskEcDhClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        super.prepareHandshakeMessageContents();
        premasterSecret = generatePremasterSecret(premasterSecret);
        preparePremasterSecret(msg);
    }

    private byte[] generatePremasterSecret(byte[] ecdhValue) {

        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(ecdhValue.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("PremasterSecret: dhValue Length: " + ecdhValue.length);
            outputStream.write(ecdhValue);
            LOGGER.debug("PremasterSecret: dhValue" + ecdhValue);
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PremasterSecret: " + tempPremasterSecret);
        return tempPremasterSecret;
    }

    @Override
    public void prepareAfterParse() {
        super.prepareAfterParse();
        premasterSecret = generatePremasterSecret(premasterSecret);
        preparePremasterSecret(msg);
    }
}
