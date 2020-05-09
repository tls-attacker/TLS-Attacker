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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.*;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

public class EmptyClientKeyExchangePreparator<T extends EmptyClientKeyExchangeMessage> extends
        ClientKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected byte[] random;
    protected final T msg;
    protected byte[] premasterSecret;

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

    protected byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        if (modulus.compareTo(BigInteger.ZERO) == 0) {
            LOGGER.warn("Modulus is ZERO. Returning empty premaster Secret");
            return new byte[0];
        }
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey.abs(), modulus.abs()));
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected byte[] computeECPremasterSecret(EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        Point sharedPoint = curve.mult(privateKey, publicKey);
        int elementLenght = ArrayConverter.bigIntegerToByteArray(sharedPoint.getX().getModulus()).length;
        return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getX().getData(), elementLenght);
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);

        if (!chooser.getContext().getClientCertificate().isEmpty()) {

            String algorithm = chooser.getContext().getClientCertificate().getCertificateAt(0)
                    .getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().toString();
            if (algorithm == "1.2.840.113549.1.3.1") {
                premasterSecret = calculatePremasterSecret(chooser.getClientDhModulus(),
                        chooser.getDhClientPrivateKey(), chooser.getDhClientPublicKey());
            } else if (algorithm == "1.2.840.10045.2.1") {
                if (clientMode) {

                    NamedGroup usedGroup = chooser.getSelectedNamedGroup();
                    // NOTE: if this is not the same group as the one the
                    // certificate resides on it won't work anyway.
                    LOGGER.debug("PMS used Group: " + usedGroup.name());

                    EllipticCurve curve = CurveFactory.getCurve(usedGroup);
                    Point publicKey;
                    publicKey = chooser.getServerEcPublicKey();
                    premasterSecret = computeECPremasterSecret(curve, publicKey, chooser.getClientEcPrivateKey());
                } else {
                    LOGGER.debug("Not Implemented.");
                }
            }
            preparePremasterSecret(msg);
        }

        // premasterSecret =
        // calculatePremasterSecret(msg.getComputations().getModulus().getValue(),
        // msg.getComputations()
        // .getPrivateKey().getValue(),
        // msg.getComputations().getPublicKey().getValue());
        // preparePremasterSecret(msg);
    }

}
