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
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskRsaClientKeyExchangePreparator
        extends RSAClientKeyExchangePreparator<PskRsaClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskRsaClientKeyExchangeMessage msg;
    private SilentByteArrayOutputStream outputStream;

    public PskRsaClientKeyExchangePreparator(
            Chooser chooser, PskRsaClientKeyExchangeMessage message) {
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
    protected byte[] manipulatePremasterSecret(byte[] premasterSecret) {
        outputStream = new SilentByteArrayOutputStream();
        outputStream.write(
                DataConverter.intToBytes(
                        HandshakeByteLength.PREMASTER_SECRET,
                        HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
        outputStream.write(premasterSecret);
        outputStream.write(
                DataConverter.intToBytes(
                        chooser.getConfig().getDefaultPSKKey().length,
                        HandshakeByteLength.PSK_LENGTH));
        outputStream.write(chooser.getConfig().getDefaultPSKKey());
        byte[] tempPremasterSecret = outputStream.toByteArray();
        return tempPremasterSecret;
    }
}
