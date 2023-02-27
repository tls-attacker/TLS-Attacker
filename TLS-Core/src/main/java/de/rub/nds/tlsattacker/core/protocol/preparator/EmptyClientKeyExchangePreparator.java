/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.certificate.CertificateAnalyzer;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
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
        prepareAfterParse();
    }

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        random = msg.getComputations().getClientServerRandom().getValue();
        LOGGER.debug(
                "ClientServerRandom: "
                        + ArrayConverter.bytesToHexString(
                                msg.getComputations().getClientServerRandom().getValue()));
    }

    protected byte[] calculateDhPremasterSecret(
            BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        if (modulus.compareTo(BigInteger.ZERO) == 0) {
            LOGGER.warn("Modulus is ZERO. Returning empty premaster Secret");
            return new byte[0];
        }
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey.abs(), modulus.abs()));
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug(
                "PremasterSecret: "
                        + ArrayConverter.bytesToHexString(
                                msg.getComputations().getPremasterSecret().getValue()));
    }

    protected byte[] computeECPremasterSecret(
            EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        Point sharedPoint = curve.mult(privateKey, publicKey);
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                sharedPoint.getFieldX().getData(), elementLength);
    }

    @Override
    public void prepareAfterParse() {
        msg.prepareComputations();
        prepareClientServerRandom(msg);

        if (chooser.getContext().getTlsContext().getClientCertificateChain() != null
                && !chooser.getContext()
                        .getTlsContext()
                        .getClientCertificateChain()
                        .getCertificateList()
                        .isEmpty()) {

            X509PublicKeyType certificateKeyType =
                    CertificateAnalyzer.getCertificateKeyType(
                            chooser.getContext()
                                    .getTlsContext()
                                    .getClientCertificateChain()
                                    .getLeaf());
            KeyExchangeAlgorithm keyExchangeAlgorithm =
                    AlgorithmResolver.getKeyExchangeAlgorithm(chooser.getSelectedCipherSuite());
            if (keyExchangeAlgorithm.isKeyExchangeDh() || keyExchangeAlgorithm.isKeyExchangeDhe()) {
                computeDhKeyExchangePms();
            } else if (keyExchangeAlgorithm.isEC()) {
                computeEcKeyExchangePms();
            } else {
                LOGGER.warn(
                        "KEX with "
                                + certificateKeyType.name()
                                + " not Implemented. Using new byte[0] as PMS");
                premasterSecret = new byte[0];
            }
        } else {
            premasterSecret = new byte[0];
        }
        preparePremasterSecret(msg);
    }

    public void computeDhKeyExchangePms() {
        BigInteger modulus = chooser.getDhKeyExchangeModulus();
        msg.getComputations().setDhModulus(modulus);
        BigInteger publicKey = chooser.getDhKeyExchangePeerPublicKey();
        msg.getComputations().setDhPeerPublicKey(publicKey);
        BigInteger privateKey = chooser.getDhKeyExchangePrivateKey();
        msg.getComputations().setPrivateKey(privateKey);
        premasterSecret =
                calculateDhPremasterSecret(
                        msg.getComputations().getDhModulus().getValue(),
                        msg.getComputations().getPrivateKey().getValue(),
                        msg.getComputations().getDhPeerPublicKey().getValue());
    }

    public void computeEcKeyExchangePms() {
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        LOGGER.debug("PMS used Group: " + usedGroup.name());
        EllipticCurve curve =
                ((NamedEllipticCurveParameters) usedGroup.getGroupParameters()).getCurve();
        Point publicKey = chooser.getEcKeyExchangePeerPublicKey();
        msg.getComputations().setEcPublicKeyX(publicKey.getFieldX().getData());
        msg.getComputations().setEcPublicKeyY(publicKey.getFieldY().getData());
        publicKey =
                curve.getPoint(
                        msg.getComputations().getEcPublicKeyX().getValue(),
                        msg.getComputations().getEcPublicKeyY().getValue());
        msg.getComputations().setPrivateKey(chooser.getEcKeyExchangePrivateKey());
        BigInteger privateKey = msg.getComputations().getPrivateKey().getValue();
        premasterSecret = computeECPremasterSecret(curve, publicKey, privateKey);
    }
}
