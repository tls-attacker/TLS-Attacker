/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PublicKeyType;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

public class EmptyClientKeyExchangePreparator<T extends EmptyClientKeyExchangeMessage>
    extends ClientKeyExchangePreparator<T> {

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

    protected byte[] calculateDhPremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
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
        int elementLength = ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
        return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getFieldX().getData(), elementLength);
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);

        if (chooser.getContext().getClientCertificate() != null
            && !chooser.getContext().getClientCertificate().isEmpty()) {

            String algorithm = chooser.getContext().getClientCertificate().getCertificateAt(0).getSubjectPublicKeyInfo()
                .getAlgorithm().getAlgorithm().toString();
            if (PublicKeyType.fromOid(algorithm) == PublicKeyType.DH) {
                BigInteger modulus = chooser.getClientDhModulus();
                BigInteger publicKey = chooser.getServerDhPublicKey();
                BigInteger privateKey = chooser.getClientDhPrivateKey();
                premasterSecret = calculateDhPremasterSecret(modulus, privateKey, publicKey);
            } else if (PublicKeyType.fromOid(algorithm) == PublicKeyType.ECDSA) {
                if (clientMode) {
                    NamedGroup usedGroup = chooser.getSelectedNamedGroup();
                    LOGGER.debug("PMS used Group: " + usedGroup.name());

                    EllipticCurve curve = CurveFactory.getCurve(usedGroup);
                    Point publicKey = chooser.getServerEcPublicKey();
                    BigInteger privateKey = chooser.getClientEcPrivateKey();
                    premasterSecret = computeECPremasterSecret(curve, publicKey, privateKey);
                } else {
                    LOGGER.debug("Not Implemented.");
                }
            }
            preparePremasterSecret(msg);
        }
    }

}
