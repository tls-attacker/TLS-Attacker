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
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskClientKeyExchangePreparator extends ClientKeyExchangePreparator<PskClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] premasterSecret;
    private byte[] clientRandom;
    private final PskClientKeyExchangeMessage msg;
    private ByteArrayOutputStream outputStream;

    public PskClientKeyExchangePreparator(Chooser chooser, PskClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        msg.prepareComputations();
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
        prepareClientServerRandom(msg);
    }

    public byte[] generatePremasterSecret() {
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(ArrayConverter.intToBytes(HandshakeByteLength.PSK_ZERO, chooser.getConfig()
                    .getDefaultPSKKey().length));
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

    private void preparePremasterSecret(PskClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareClientServerRandom(PskClientKeyExchangeMessage msg) {
        clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientRandom);
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        if (!clientMode) {
            msg.prepareComputations();
            premasterSecret = generatePremasterSecret();
            preparePremasterSecret(msg);
            prepareClientServerRandom(msg);
        }
    }
}
