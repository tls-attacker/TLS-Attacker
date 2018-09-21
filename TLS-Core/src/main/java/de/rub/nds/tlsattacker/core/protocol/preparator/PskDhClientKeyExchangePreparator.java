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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDhClientKeyExchangePreparator extends DHClientKeyExchangePreparator<PskDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskDhClientKeyExchangeMessage msg;
    private ByteArrayOutputStream outputStream;

    public PskDhClientKeyExchangePreparator(Chooser chooser, PskDhClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        super.prepareHandshakeMessageContents();
    }

    @Override
    protected byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        byte[] otherSecret = super.calculatePremasterSecret(modulus, privateKey, publicKey);
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(otherSecret.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("OtherSecret Length: " + otherSecret.length);
            outputStream.write(otherSecret);
            LOGGER.debug("OtherSecret: " + ArrayConverter.bytesToHexString(otherSecret));
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PSK PremasterSecret: " + ArrayConverter.bytesToHexString(tempPremasterSecret));
        return tempPremasterSecret;
    }
}
