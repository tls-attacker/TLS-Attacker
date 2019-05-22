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
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.PWDClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PWDClientKeyExchangePreparator extends ClientKeyExchangePreparator<PWDClientKeyExchangeMessage> {
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
        msg.getComputations().setCurve(
                ECNamedCurveTable.getParameterSpec(chooser.getSelectedNamedGroup().getJavaName()).getCurve());
        LOGGER.debug(chooser.getSelectedNamedGroup().getJavaName());

        try {
            preparePE(msg);
        } catch (CryptoException e) {
            throw new PreparationException("Failed to generate PE", e);
        }
        prepareScalarElement(msg);
        byte[] premasterSecret = generatePremasterSecret(msg.getComputations().getPE(), msg.getComputations()
                .getPrivate());
        preparePremasterSecret(msg, premasterSecret);
        prepareClientServerRandom(msg);
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        if (!clientMode) {
            msg.prepareComputations();
            byte[] premasterSecret = generatePremasterSecret(chooser.getContext().getPWDPE(), chooser.getContext()
                    .getServerPWDPrivate());
            preparePremasterSecret(msg, premasterSecret);
            prepareClientServerRandom(msg);
        }
    }

    protected void preparePE(PWDClientKeyExchangeMessage msg) throws CryptoException {
        ECPoint PE = PWDComputations.computePE(chooser, msg.getComputations().getCurve());
        msg.getComputations().setPE(PE);

        LOGGER.debug("PE.x: "
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(PE.getXCoord().toBigInteger())));
    }

    protected MacAlgorithm getMacAlgorithm(CipherSuite suite) {
        if (suite.isSHA256()) {
            return MacAlgorithm.HMAC_SHA256;
        } else if (suite.isSHA384()) {
            return MacAlgorithm.HMAC_SHA384;
        } else if (suite.name().endsWith("SHA")) {
            return MacAlgorithm.HMAC_SHA1;
        } else {
            throw new PreparationException("Unsupported Mac Algorithm for suite " + suite.toString());
        }
    }

    protected List<ECPointFormat> getPointFormatList() {
        List<ECPointFormat> sharedPointFormats = new ArrayList<>(chooser.getClientSupportedPointFormats());

        if (sharedPointFormats.isEmpty()) {
            LOGGER.warn("Don't know which point format to use for PWD. " + "Check if pointFormats is set in config.");
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
            sharedPointFormats = new ArrayList<>(chooser.getConfig().getDefaultClientSupportedPointFormats());
        }

        return sharedPointFormats;
    }

    protected void prepareScalarElement(PWDClientKeyExchangeMessage msg) {
        ECCurve curve = msg.getComputations().getCurve();
        PWDComputations.PWDKeyMaterial keyMaterial = PWDComputations.generateKeyMaterial(curve, msg.getComputations()
                .getPE(), chooser);

        msg.getComputations().setPrivate(keyMaterial.priv);
        LOGGER.debug("Private: "
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(keyMaterial.priv)));

        prepareScalar(msg, keyMaterial.scalar);
        prepareScalarLength(msg);

        prepareElement(msg, keyMaterial.element);
        prepareElementLength(msg);
    }

    protected void prepareScalar(PWDClientKeyExchangeMessage msg, BigInteger scalar) {
        msg.setScalar(ArrayConverter.bigIntegerToByteArray(scalar));
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(scalar)));
    }

    protected void prepareScalarLength(PWDClientKeyExchangeMessage msg) {
        msg.setScalarLength(msg.getScalar().getValue().length);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength());
    }

    protected void prepareElement(PWDClientKeyExchangeMessage msg, ECPoint element) {
        List<ECPointFormat> ecPointFormats = getPointFormatList();
        try {
            byte[] serializedElement = ECCUtilsBCWrapper.serializeECPoint(ecPointFormats.toArray(new ECPointFormat[0]),
                    element);
            msg.setElement(serializedElement);
            LOGGER.debug("Element: " + ArrayConverter.bytesToHexString(serializedElement));
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize PWD element", ex);
        }
    }

    protected void prepareElementLength(PWDClientKeyExchangeMessage msg) {
        msg.setElementLength(msg.getElement().getValue().length);
        LOGGER.debug("ElementLength: " + msg.getElementLength());
    }

    private byte[] generatePremasterSecret(ECPoint PE, BigInteger priv) {
        ECCurve curve = PE.getCurve();
        ECPoint peerElement;
        BigInteger peerScalar;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            peerElement = chooser.getContext().getServerPWDElement();
            peerScalar = chooser.getContext().getServerPWDScalar();
        } else {
            peerElement = curve.decodePoint(msg.getElement().getValue());
            peerScalar = new BigInteger(1, msg.getScalar().getValue());
        }
        if (peerElement == null || peerScalar == null) {
            LOGGER.warn("Missing peer element or scalar, returning empty premaster secret");
            return new byte[0];
        }
        ECPoint sharedSecret = PE.multiply(peerScalar).add(peerElement).multiply(priv).normalize();
        return ArrayConverter.bigIntegerToByteArray(sharedSecret.getXCoord().toBigInteger());
    }

    private void preparePremasterSecret(PWDClientKeyExchangeMessage msg, byte[] premasterSecret) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareClientServerRandom(PWDClientKeyExchangeMessage msg) {
        byte[] clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientRandom);
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

}
