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
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import java.util.Arrays;

public class PskRsaClientKeyExchangePreparator extends RSAClientKeyExchangePreparator<PskRsaClientKeyExchangeMessage> {

    private final PskRsaClientKeyExchangeMessage msg;
    private ByteArrayOutputStream outputStream;

    public PskRsaClientKeyExchangePreparator(Chooser chooser, PskRsaClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        super.prepareHandshakeMessageContents();
        premasterSecret = generatePremasterSecret(msg.getComputations().getPremasterSecret().getValue());
        preparePremasterSecret(msg);
    }

    private byte[] generatePremasterSecret(byte[] randomValue) {
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(HandshakeByteLength.PREMASTER_SECRET,
                    HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
            outputStream.write(randomValue);
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        return tempPremasterSecret;
    }

    @Override
    public void prepareAfterParse() {
        // Decrypt premaster secret
        msg.prepareComputations();
        byte[] paddedPremasterSecret = decryptPremasterSecret();
        LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));

        int keyByteLength = chooser.getRsaModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
        premasterSecret = generatePremasterSecret(Arrays.copyOfRange(paddedPremasterSecret, randomByteLength,
                paddedPremasterSecret.length));
        LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
