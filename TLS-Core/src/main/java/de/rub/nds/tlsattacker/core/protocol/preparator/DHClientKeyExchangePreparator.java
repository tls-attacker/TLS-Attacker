/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.protocol.message.computations.DHClientComputations;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangePreparator extends ClientKeyExchangePreparator<DHClientKeyExchangeMessage> {

    private BigInteger clientPublicKey;
    private byte[] premasterSecret;
    private byte[] random;
    private byte[] masterSecret;
    private final DHClientKeyExchangeMessage msg;

    public DHClientKeyExchangePreparator(Chooser chooser, DHClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg);
        setComputationServerPublicKey(msg);

        premasterSecret = calculatePremasterSecret(msg.getComputations().getModulus().getValue(), msg.getComputations()
                .getPrivateKey().getValue(), msg.getComputations().getServerPublicKey().getValue());
        preparePremasterSecret(msg);
        clientPublicKey = calculatePublicKey(msg.getComputations().getGenerator().getValue(), msg.getComputations()
                .getModulus().getValue(), msg.getComputations().getPrivateKey().getValue());
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        prepareClientRandom(msg);
        prepareMasterSecret(msg);
    }

    private BigInteger calculatePublicKey(BigInteger generator, BigInteger modulus, BigInteger privateKey) {
        return generator.modPow(privateKey, modulus);
    }

    private byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey, modulus));
    }

    private byte[] calculateMasterSecret(byte[] random, byte[] premasterSecret) {
        PRFAlgorithm prfAlgorithm = chooser.getPRFAlgorithm();
        masterSecret = PseudoRandomFunction.compute(prfAlgorithm, premasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        return masterSecret;

    }

    private void setComputationGenerator(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getDhGenerator());
        LOGGER.debug("Generator: " + msg.getComputations().getGenerator().getValue());
    }

    private void setComputationModulus(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getDhModulus());
        LOGGER.debug("Modulus: " + msg.getComputations().getModulus().getValue());
    }

    private void preparePremasterSecret(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void preparePublicKey(DHClientKeyExchangeMessage msg) {
        msg.setPublicKey(clientPublicKey.toByteArray());
        LOGGER.debug("PublicKey: " + msg.getPublicKey().getValue());
    }

    private void preparePublicKeyLength(DHClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void prepareClientRandom(DHClientKeyExchangeMessage msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(random);
        random = msg.getComputations().getClientRandom().getValue();
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareMasterSecret(DHClientKeyExchangeMessage msg) {
        masterSecret = calculateMasterSecret(random, premasterSecret);
        msg.getComputations().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getMasterSecret().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        BigInteger privateKey = chooser.getDhServerPrivateKey();
        BigInteger clientPublic = new BigInteger(1, msg.getPublicKey().getValue());
        msg.prepareComputations();
        premasterSecret = calculatePremasterSecret(chooser.getDhModulus(), privateKey, clientPublic);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
        calculateMasterSecret(random, premasterSecret);
        prepareMasterSecret(msg);
    }

    private void setComputationPrivateKey(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(chooser.getDhClientPrivateKey());
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().toString());
    }

    private void setComputationServerPublicKey(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setServerPublicKey(chooser.getDhServerPublicKey());
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getServerPublicKey().getValue().toString());
    }
}
