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
import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PSKPremasterComputations;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
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
        msg.setIdentity(chooser.getConfig().getDefaultPSKIdentity());
        msg.setIdentityLength(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKIdentity().length, 2));
        msg.prepareComputations();
        // byte[] random = ArrayConverter.concatenate(chooser.getClientRandom(),
        // chooser.getServerRandom());
        // msg.getComputations().setClientRandom(random);

        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    private byte[] generatePremasterSecret() {
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length, 2));
            outputStream.write(ArrayConverter.intToBytes(0, chooser.getConfig().getDefaultPSKKey().length));
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length, 2));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
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

    private void prepareClientRandom(PSKClientKeyExchangeMessage msg) {
        // TODO spooky
        clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        msg.prepareComputations();
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
