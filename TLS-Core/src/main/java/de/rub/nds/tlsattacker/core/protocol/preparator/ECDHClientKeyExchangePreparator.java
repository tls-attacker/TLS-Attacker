/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256R1;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangePreparator<T extends ECDHClientKeyExchangeMessage>
        extends ClientKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected byte[] premasterSecret;
    protected byte[] random;
    protected final T msg;

    public ECDHClientKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing ECDHClientExchangeMessage");
        msg.prepareComputations();
        setSerializedPublicKey();
        prepareSerializedPublicKeyLength(msg);
        prepareAfterParse();
    }

    protected byte[] computePremasterSecret(
            EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        if (curve instanceof RFC7748Curve) {
            RFC7748Curve rfc7748Curve = (RFC7748Curve) curve;
            return rfc7748Curve.computeSharedSecretFromDecodedPoint(
                    msg.getComputations().getPrivateKey().getValue(), publicKey);
        } else {
            Point sharedPoint = curve.mult(privateKey, publicKey);
            if (sharedPoint == null) {
                LOGGER.warn("Computed null shared point. Using basepoint instead");
                sharedPoint = curve.getBasePoint();
            }
            if (sharedPoint.isAtInfinity()) {
                LOGGER.warn(
                        "Computed shared secrets as point in infinity. Using new byte[1] as PMS");
                return new byte[1];
            }
            int elementLength =
                    ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus())
                            .length;
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    sharedPoint.getFieldX().getData(), elementLength);
        }
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: {}", msg.getPublicKeyLength().getValue());
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: {}", msg.getComputations().getPremasterSecret().getValue());
    }

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug(
                "ClientServerRandom: {}", msg.getComputations().getClientServerRandom().getValue());
    }

    @Override
    public void prepareAfterParse() {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        NamedGroup usedGroup = getSuitableNamedGroup();
        LOGGER.debug("PMS used Group: {}", usedGroup.name());
        if (msg.getComputations().getPrivateKey() == null) {
            setComputationPrivateKey(msg);
        }
        CyclicGroup<?> group = usedGroup.getGroupParameters().getGroup();
        Point publicKey = chooser.getEcKeyExchangePeerPublicKey();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }

        premasterSecret =
                computePremasterSecret(
                        curve, publicKey, msg.getComputations().getPrivateKey().getValue());
        preparePremasterSecret(msg);
    }

    private void setSerializedPublicKey() {
        NamedGroup usedGroup = getSuitableNamedGroup();

        CyclicGroup<?> group = usedGroup.getGroupParameters().getGroup();
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn("Selected group is not an EllipticCurve. Using SECP256R1");
            curve = new EllipticCurveSECP256R1();
        }

        LOGGER.debug("PublicKey used Group: {}", usedGroup.name());
        ECPointFormat pointFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        LOGGER.debug("EC Point format: {}", pointFormat.name());
        setComputationPrivateKey(msg);
        byte[] publicKeyBytes;
        BigInteger privateKey = msg.getComputations().getPrivateKey().getValue();

        if (curve instanceof RFC7748Curve) {
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;
            publicKeyBytes = rfcCurve.computePublicKey(privateKey);
        } else {
            Point publicKey = curve.mult(privateKey, curve.getBasePoint());
            msg.getComputations().setPublicKeyX(publicKey.getFieldX().getData());
            msg.getComputations().setPublicKeyY(publicKey.getFieldY().getData());
            publicKey =
                    curve.getPoint(
                            msg.getComputations().getPublicKeyX().getValue(),
                            msg.getComputations().getPublicKeyY().getValue());
            publicKeyBytes =
                    PointFormatter.formatToByteArray(
                            usedGroup.getGroupParameters(), publicKey, pointFormat.getFormat());
        }
        msg.setPublicKey(publicKeyBytes);
    }

    private NamedGroup getSuitableNamedGroup() {
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        if (!usedGroup.isEcGroup() || usedGroup.isGost()) {
            usedGroup = NamedGroup.SECP256R1;
            LOGGER.warn(
                    "Selected NamedGroup {} is not suitable for ECDHClientKeyExchange message. Using {} instead.",
                    chooser.getSelectedNamedGroup(),
                    usedGroup);
        }
        return usedGroup;
    }

    protected void setComputationPrivateKey(T msg) {
        LOGGER.debug("Preparing client key");
        msg.getComputations().setPrivateKey(chooser.getEcKeyExchangePrivateKey());
        LOGGER.debug(
                "Computation PrivateKey: {}", msg.getComputations().getPrivateKey().getValue());
    }
}
