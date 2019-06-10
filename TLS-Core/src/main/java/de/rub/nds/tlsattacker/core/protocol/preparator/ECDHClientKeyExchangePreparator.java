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
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec_.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec_.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec_.Point;
import de.rub.nds.tlsattacker.core.crypto.ec_.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X448;

public class ECDHClientKeyExchangePreparator<T extends ECDHClientKeyExchangeMessage> extends
        ClientKeyExchangePreparator<T> {

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

    protected ECDomainParameters getDomainParameters(EllipticCurveType curveType, NamedGroup namedGroup) {
        InputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(new byte[] { curveType.getValue() },
                namedGroup.getValue()));
        try {
            return ECCUtilsBCWrapper.readECParameters(new NamedGroup[] { namedGroup },
                    new ECPointFormat[] { ECPointFormat.UNCOMPRESSED }, stream);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }
    }

    protected byte[] computePremasterSecret(EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        Point sharedPoint = curve.mult(privateKey, publicKey);
        int elementLenght = ArrayConverter.bigIntegerToByteArray(sharedPoint.getX().getModulus()).length;
        return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getX().getData(), elementLenght);
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        LOGGER.debug("PMS used Group: " + usedGroup.name());
        if (msg.getComputations().getPrivateKey() == null) {
            setComputationPrivateKey(msg, clientMode);
        }

        if (usedGroup == NamedGroup.ECDH_X25519) {
            // TODO ServerMode
            byte[] privateKeyBytes = msg.getComputations().getPrivateKey().getValue().toByteArray();
            if (privateKeyBytes.length != 32) {
                LOGGER.warn("ECDH_25519 private Key is not 32 byte - using as much as possible and padding the rest with Zeros.");
                privateKeyBytes = Arrays.copyOf(privateKeyBytes, 32);
            }
            premasterSecret = new byte[32];
            X25519.precompute();
            X25519.scalarMult(privateKeyBytes, 0, chooser.getServerEcPublicKey().getByteX(), 0, premasterSecret, 0);
        } else if (usedGroup == NamedGroup.ECDH_X448) {
            // TODO ServerMode
            byte[] privateKeyBytes = msg.getComputations().getPrivateKey().getValue().toByteArray();
            if (privateKeyBytes.length != 56) {
                LOGGER.warn("ECDH_X448 private Key is not 56 byte - using as much as possible and padding the rest with Zeros.");
                privateKeyBytes = Arrays.copyOf(privateKeyBytes, 56);
            }
            premasterSecret = new byte[56];
            X448.precompute();
            X448.scalarMult(privateKeyBytes, 0, chooser.getServerEcPublicKey().getByteX(), 0, premasterSecret, 0);
        } else {
            EllipticCurve curve = CurveFactory.getCurve(usedGroup);
            Point publicKey;
            if (clientMode) {
                publicKey = curve
                        .getPoint(chooser.getServerEcPublicKey().getX(), chooser.getServerEcPublicKey().getY());
                msg.getComputations().setPublicKeyX(publicKey.getX().getData());
                msg.getComputations().setPublicKeyY(publicKey.getY().getData());
            } else {
                publicKey = PointFormatter.formatFromByteArray(usedGroup, msg.getPublicKey().getValue());
            }
            LOGGER.debug("PublicKey used:" + publicKey.toString());
            LOGGER.debug("PrivateKey used:" + msg.getComputations().getPrivateKey().getValue());
            premasterSecret = computePremasterSecret(curve, publicKey, msg.getComputations().getPrivateKey().getValue());
        }
        preparePremasterSecret(msg);
    }

    private void setSerializedPublicKey() {
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        LOGGER.debug("PublicKey used Group: " + usedGroup.name());
        ECPointFormat pointFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        LOGGER.debug("EC Point format: " + pointFormat.name());
        setComputationPrivateKey(msg, true);
        byte[] curveBytes = null;
        byte[] privateKeyBytes = msg.getComputations().getPrivateKey().getValue().toByteArray();

        if (usedGroup == NamedGroup.ECDH_X25519) {
            if (privateKeyBytes.length != 32) {
                LOGGER.warn("ECDH_25519 private Key is not 32 byte - using as much as possible and padding the rest with Zeros.");
                privateKeyBytes = Arrays.copyOf(privateKeyBytes, 32);
            }
            curveBytes = new byte[32];
            X25519.precompute();
            X25519.scalarMultBase(privateKeyBytes, 0, curveBytes, 0);
        } else if (usedGroup == NamedGroup.ECDH_X448) {
            if (privateKeyBytes.length != 56) {
                LOGGER.warn("ECDH_448 private Key is not 56 byte - using as much as possible and padding the rest with Zeros.");
                privateKeyBytes = Arrays.copyOf(privateKeyBytes, 56);
            }
            curveBytes = new byte[56];
            X448.precompute();
            X448.scalarMultBase(privateKeyBytes, 0, curveBytes, 0);
        } else {
            EllipticCurve curve = CurveFactory.getCurve(usedGroup);
            Point publicKey = curve.mult(msg.getComputations().getPrivateKey().getValue(), curve.getBasePoint());
            msg.getComputations().setPublicKeyX(publicKey.getX().getData());
            msg.getComputations().setPublicKeyY(publicKey.getY().getData());
            publicKey = curve.getPoint(msg.getComputations().getPublicKeyX().getValue(), msg.getComputations()
                    .getPublicKeyY().getValue());
            curveBytes = PointFormatter.formatToByteArray(publicKey, pointFormat);
        }
        msg.setPublicKey(curveBytes);
    }

    protected void setComputationPrivateKey(T msg, boolean clientMode) {
        if (clientMode) {
            LOGGER.debug("Using Client PrivateKey");
            msg.getComputations().setPrivateKey(chooser.getClientEcPrivateKey());
        } else {
            LOGGER.debug("Using Server PrivateKey");
            msg.getComputations().setPrivateKey(chooser.getServerEcPrivateKey());
        }
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }
}
