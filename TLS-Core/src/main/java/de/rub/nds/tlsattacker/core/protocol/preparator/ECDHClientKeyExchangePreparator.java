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
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.*;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHClientKeyExchangePreparator<T extends ECDHClientKeyExchangeMessage<?>>
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
        prepareAfterParse(true);
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
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
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
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        NamedGroup usedGroup = getSuitableNamedGroup();
        LOGGER.debug("PMS used Group: " + usedGroup.name());
        if (msg.getComputations().getPrivateKey() == null) {
            setComputationPrivateKey(msg, clientMode);
        }
        EllipticCurve curve = CurveFactory.getCurve(usedGroup);
        Point publicKey;

        if (clientMode) {
            publicKey = chooser.getServerEcPublicKey();
        } else {
            publicKey =
                    PointFormatter.formatFromByteArray(usedGroup, msg.getPublicKey().getValue());
        }
        premasterSecret =
                computePremasterSecret(
                        curve, publicKey, msg.getComputations().getPrivateKey().getValue());
        preparePremasterSecret(msg);
    }

    private void setSerializedPublicKey() {
        NamedGroup usedGroup = getSuitableNamedGroup();
        LOGGER.debug("PublicKey used Group: " + usedGroup.name());
        ECPointFormat pointFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        LOGGER.debug("EC Point format: " + pointFormat.name());
        setComputationPrivateKey(msg, true);
        byte[] publicKeyBytes;
        BigInteger privateKey = msg.getComputations().getPrivateKey().getValue();
        EllipticCurve curve = CurveFactory.getCurve(usedGroup);
        if (usedGroup == NamedGroup.ECDH_X25519 || usedGroup == NamedGroup.ECDH_X448) {
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
            publicKeyBytes = PointFormatter.formatToByteArray(usedGroup, publicKey, pointFormat);
        }
        msg.setPublicKey(publicKeyBytes);
    }

    private NamedGroup getSuitableNamedGroup() {
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        if (!usedGroup.isCurve() || usedGroup.isGost()) {
            usedGroup = NamedGroup.SECP256R1;
            LOGGER.warn(
                    "Selected NamedGroup {} is not suitable for ECDHClientKeyExchange message. Using {} instead.",
                    chooser.getSelectedNamedGroup(),
                    usedGroup);
        }
        return usedGroup;
    }

    protected void setComputationPrivateKey(T msg, boolean clientMode) {
        if (clientMode) {
            LOGGER.debug("Using Client PrivateKey");
            msg.getComputations().setPrivateKey(chooser.getClientEcPrivateKey());
        } else {
            LOGGER.debug("Using Server PrivateKey");
            msg.getComputations().setPrivateKey(chooser.getServerEcPrivateKey());
        }
        LOGGER.debug(
                "Computation PrivateKey: "
                        + msg.getComputations().getPrivateKey().getValue().toString());
    }
}
