/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskClientKeyExchangePreparator
        extends ClientKeyExchangePreparator<PskClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private byte[] premasterSecret;
    private byte[] clientRandom;
    private final PskClientKeyExchangeMessage msg;
    private SilentByteArrayOutputStream outputStream;

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
        byte[] psk = chooser.getConfig().getDefaultPSKKey();
        outputStream = new SilentByteArrayOutputStream();
        outputStream.write(DataConverter.intToBytes(psk.length, HandshakeByteLength.PSK_LENGTH));
        if (psk.length > 0) {
            outputStream.write(DataConverter.intToBytes(HandshakeByteLength.PSK_ZERO, psk.length));
        }
        outputStream.write(DataConverter.intToBytes(psk.length, HandshakeByteLength.PSK_LENGTH));
        outputStream.write(psk);
        byte[] tempPremasterSecret = outputStream.toByteArray();
        return tempPremasterSecret;
    }

    private void preparePremasterSecret(PskClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: {}", msg.getComputations().getPremasterSecret().getValue());
    }

    private void prepareClientServerRandom(PskClientKeyExchangeMessage msg) {
        clientRandom =
                DataConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientRandom);
        LOGGER.debug(
                "ClientServerRandom: {}", msg.getComputations().getClientServerRandom().getValue());
    }

    @Override
    public void prepareAfterParse() {
        msg.prepareComputations();
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
        prepareClientServerRandom(msg);
    }
}
