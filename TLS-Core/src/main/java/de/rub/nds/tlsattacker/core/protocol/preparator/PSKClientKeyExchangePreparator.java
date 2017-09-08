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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PSKClientKeyExchangePreparator extends ClientKeyExchangePreparator<PSKClientKeyExchangeMessage> {

    private byte[] padding;
    private byte[] premasterSecret;
    private byte[] clientRandom;
    private byte[] masterSecret;
    private byte[] encrypted;
    private final PSKClientKeyExchangeMessage msg;
    private PSKPremasterComputations comps;
    private ByteArrayOutputStream outputStream;

    public PSKClientKeyExchangePreparator(Chooser chooser, PSKClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getConfig().getDefaultPSKIdentity().toByteArray());
        msg.setIdentityLength(chooser.getConfig().getDefaultPSKIdentity().toByteArray().length);
        msg.prepareComputations();
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
    }

    private byte[] generatePremasterSecret() {
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().bitLength()/8, 2));
            outputStream.write(ArrayConverter.intToBytes(0, chooser.getConfig().getDefaultPSKKey().bitLength()/8));
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().bitLength()/8, 2));
            outputStream.write(chooser.getConfig().getDefaultPSKKey().toByteArray());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
       byte[] tempPremasterSecret = outputStream.toByteArray();
       return tempPremasterSecret; 
    }

    private void preparePremasterSecret(PSKClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        // Decrypt premaster secret
        msg.prepareComputations();
       // byte[] paddedPremasterSecret = decryptPremasterSecret();
       // LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));

        int keyByteLength = chooser.getRsaModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
        //premasterSecret = Arrays.copyOfRange(paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
       // LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));
        preparePremasterSecret(msg);
    }
}
