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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDClientKeyExchangePreparator
        extends ClientKeyExchangePreparator<PWDClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final PWDClientKeyExchangeMessage msg;

    public PWDClientKeyExchangePreparator(Chooser chooser, PWDClientKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing PWDClientKeyExchangeMessage");
        msg.prepareComputations();
        EllipticCurve curve = CurveFactory.getCurve(chooser.getSelectedNamedGroup());
        LOGGER.debug(chooser.getSelectedNamedGroup().getJavaName());

        try {
            preparePasswordElement(msg);
        } catch (CryptoException e) {
            throw new PreparationException("Failed to generate password element", e);
        }
        prepareScalarElement(msg);
        byte[] premasterSecret =
                generatePremasterSecret(
                        msg.getComputations().getPasswordElement(),
                        msg.getComputations().getPrivateKeyScalar(),
                        curve);
        preparePremasterSecret(msg, premasterSecret);
        prepareClientServerRandom(msg);
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        if (!clientMode) {
            msg.prepareComputations();
            EllipticCurve curve = CurveFactory.getCurve(chooser.getSelectedNamedGroup());
            byte[] premasterSecret =
                    generatePremasterSecret(
                            chooser.getContext().getTlsContext().getPWDPE(),
                            chooser.getContext().getTlsContext().getServerPWDPrivate(),
                            curve);
            preparePremasterSecret(msg, premasterSecret);
            prepareClientServerRandom(msg);
        }
    }

    protected void preparePasswordElement(PWDClientKeyExchangeMessage msg) throws CryptoException {
        EllipticCurve curve = CurveFactory.getCurve(chooser.getSelectedNamedGroup());
        Point passwordElement = PWDComputations.computePasswordElement(chooser, curve);
        msg.getComputations().setPasswordElement(passwordElement);

        LOGGER.debug(
                "PasswordElement.x: {}",
                ArrayConverter.bigIntegerToByteArray(passwordElement.getFieldX().getData()));
    }

    protected MacAlgorithm getMacAlgorithm(CipherSuite suite) {
        if (suite.isSHA256()) {
            return MacAlgorithm.HMAC_SHA256;
        } else if (suite.isSHA384()) {
            return MacAlgorithm.HMAC_SHA384;
        } else if (suite.name().endsWith("SHA")) {
            return MacAlgorithm.HMAC_SHA1;
        } else {
            throw new PreparationException(
                    "Unsupported Mac Algorithm for suite " + suite.toString());
        }
    }

    protected List<ECPointFormat> getPointFormatList() {
        List<ECPointFormat> sharedPointFormats =
                new ArrayList<>(chooser.getClientSupportedPointFormats());

        if (sharedPointFormats.isEmpty()) {
            LOGGER.warn(
                    "Don't know which point format to use for PWD. "
                            + "Check if pointFormats is set in config.");
            sharedPointFormats = chooser.getConfig().getDefaultClientSupportedPointFormats();
        }

        List<ECPointFormat> unsupportedFormats = new ArrayList<>();

        if (!chooser.getConfig().isEnforceSettings()) {
            List<ECPointFormat> clientPointFormats = chooser.getClientSupportedPointFormats();
            for (ECPointFormat f : sharedPointFormats) {
                if (!clientPointFormats.contains(f)) {
                    unsupportedFormats.add(f);
                }
            }
        }

        sharedPointFormats.removeAll(unsupportedFormats);
        if (sharedPointFormats.isEmpty()) {
            sharedPointFormats =
                    new ArrayList<>(chooser.getConfig().getDefaultClientSupportedPointFormats());
        }

        return sharedPointFormats;
    }

    protected void prepareScalarElement(PWDClientKeyExchangeMessage msg) {
        EllipticCurve curve = CurveFactory.getCurve(chooser.getSelectedNamedGroup());
        PWDComputations.PWDKeyMaterial keyMaterial =
                PWDComputations.generateKeyMaterial(
                        curve, msg.getComputations().getPasswordElement(), chooser);

        msg.getComputations().setPrivateKeyScalar(keyMaterial.privateKeyScalar);
        LOGGER.debug(
                "Private: {}",
                () -> ArrayConverter.bigIntegerToByteArray(keyMaterial.privateKeyScalar));

        prepareScalar(msg, keyMaterial.scalar);
        prepareScalarLength(msg);

        prepareElement(msg, keyMaterial.element);
        prepareElementLength(msg);
    }

    protected void prepareScalar(PWDClientKeyExchangeMessage msg, BigInteger scalar) {
        msg.setScalar(ArrayConverter.bigIntegerToByteArray(scalar));
        LOGGER.debug("Scalar: {}", () -> ArrayConverter.bigIntegerToByteArray(scalar));
    }

    protected void prepareScalarLength(PWDClientKeyExchangeMessage msg) {
        msg.setScalarLength(msg.getScalar().getValue().length);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength());
    }

    protected void prepareElement(PWDClientKeyExchangeMessage msg, Point element) {
        byte[] serializedElement =
                PointFormatter.formatToByteArray(
                        chooser.getConfig().getDefaultSelectedNamedGroup(),
                        element,
                        chooser.getConfig().getDefaultSelectedPointFormat());
        msg.setElement(serializedElement);
        LOGGER.debug("Element: {}", serializedElement);
    }

    protected void prepareElementLength(PWDClientKeyExchangeMessage msg) {
        msg.setElementLength(msg.getElement().getValue().length);
        LOGGER.debug("ElementLength: " + msg.getElementLength());
    }

    private byte[] generatePremasterSecret(
            Point passwordElement, BigInteger privateKeyScalar, EllipticCurve curve) {
        Point peerElement;
        BigInteger peerScalar;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            peerElement = chooser.getContext().getTlsContext().getServerPWDElement();
            peerScalar = chooser.getContext().getTlsContext().getServerPWDScalar();
        } else {
            // TODO: wrong group
            peerElement =
                    PointFormatter.formatFromByteArray(
                            chooser.getSelectedNamedGroup(), msg.getElement().getValue());
            peerScalar = new BigInteger(1, msg.getScalar().getValue());
        }
        if (peerElement == null || peerScalar == null) {
            LOGGER.warn("Missing peer element or scalar, returning empty premaster secret");
            return new byte[0];
        }
        Point sharedSecret =
                curve.mult(
                        privateKeyScalar,
                        curve.add(curve.mult(peerScalar, passwordElement), peerElement));
        return ArrayConverter.bigIntegerToByteArray(sharedSecret.getFieldX().getData());
    }

    private void preparePremasterSecret(PWDClientKeyExchangeMessage msg, byte[] premasterSecret) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: {}", msg.getComputations().getPremasterSecret().getValue());
    }

    private void prepareClientServerRandom(PWDClientKeyExchangeMessage msg) {
        byte[] clientRandom =
                ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientRandom);
        LOGGER.debug(
                "ClientServerRandom: {}", msg.getComputations().getClientServerRandom().getValue());
    }
}
