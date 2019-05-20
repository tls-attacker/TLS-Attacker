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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.PWDServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
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

public class PWDServerKeyExchangePreparator extends ServerKeyExchangePreparator<PWDServerKeyExchangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    protected final PWDServerKeyExchangeMessage msg;

    public PWDServerKeyExchangePreparator(Chooser chooser, PWDServerKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing PWDServerKeyExchangeMessage");
        msg.prepareComputations();
        prepareCurveType(msg);
        prepareNamedGroup(msg);
        prepareSalt(msg);
        prepareSaltLength(msg);

        try {
            preparePE(msg);
        } catch (CryptoException e) {
            throw new PreparationException("Failed to generate PE", e);
        }
        prepareScalarElement(msg);
    }

    protected void preparePE(PWDServerKeyExchangeMessage msg) throws CryptoException {
        ECPoint PE = PWDComputations.computePE(chooser, msg.getComputations().getCurve());
        msg.getComputations().setPE(PE);

        LOGGER.debug("PE.x: "
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(PE.getXCoord().toBigInteger())));
    }

    protected void prepareNamedGroup(PWDServerKeyExchangeMessage msg) {
        List<NamedGroup> sharedGroups = new ArrayList<>(chooser.getClientSupportedNamedGroups());
        List<NamedGroup> unsupportedGroups = new ArrayList<>();
        if (!chooser.getConfig().isEnforceSettings()) {

            List<NamedGroup> clientGroups = chooser.getServerSupportedNamedGroups();
            for (NamedGroup c : sharedGroups) {
                ECCurve curve = ECNamedCurveTable.getParameterSpec(c.getJavaName()).getCurve();
                if (!clientGroups.contains(c) || curve.getCofactor().compareTo(BigInteger.ONE) != 0
                        || curve instanceof ECCurve.F2m) {
                    unsupportedGroups.add(c);
                }
            }
            sharedGroups.removeAll(unsupportedGroups);
            if (sharedGroups.isEmpty()) {
                if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                    sharedGroups = new ArrayList<>(chooser.getConfig().getDefaultClientNamedGroups());
                } else {
                    sharedGroups = new ArrayList<>(chooser.getConfig().getDefaultServerNamedGroups());
                }
            }
        }
        msg.setNamedGroup(sharedGroups.get(0).getValue());
        msg.getComputations()
                .setCurve(ECNamedCurveTable.getParameterSpec(sharedGroups.get(0).getJavaName()).getCurve());

        LOGGER.debug("NamedGroup: " + sharedGroups.get(0).getJavaName());
    }

    protected void prepareSalt(PWDServerKeyExchangeMessage msg) {
        msg.setSalt(chooser.getServerPWDSalt());
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt().getValue()));
    }

    protected void prepareSaltLength(PWDServerKeyExchangeMessage msg) {
        msg.setSaltLength(msg.getSalt().getValue().length);
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    protected void prepareCurveType(PWDServerKeyExchangeMessage msg) {
        msg.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
    }

    protected List<ECPointFormat> getPointFormatList() {
        List<ECPointFormat> sharedPointFormats = new ArrayList<>(chooser.getServerSupportedPointFormats());

        if (sharedPointFormats.isEmpty()) {
            LOGGER.warn("Don't know which point format to use for PWD. " + "Check if pointFormats is set in config.");
            sharedPointFormats = chooser.getConfig().getDefaultServerSupportedPointFormats();
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
            sharedPointFormats = new ArrayList<>(chooser.getConfig().getDefaultServerSupportedPointFormats());
        }

        return sharedPointFormats;
    }

    protected void prepareScalarElement(PWDServerKeyExchangeMessage msg) {
        ECCurve curve = msg.getComputations().getCurve();
        BigInteger mask;
        BigInteger priv;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            mask = new BigInteger(1, chooser.getConfig().getDefaultClientPWDMask());
            priv = new BigInteger(1, chooser.getConfig().getDefaultClientPWDPrivate());
        } else {
            mask = new BigInteger(1, chooser.getConfig().getDefaultServerPWDMask());
            priv = new BigInteger(1, chooser.getConfig().getDefaultServerPWDPrivate());
        }
        mask = mask.mod(curve.getOrder());
        priv = priv.mod(curve.getOrder());
        BigInteger scalar = mask.add(priv).mod(curve.getOrder());

        ECPoint element = msg.getComputations().getPE().multiply(mask).negate().normalize();

        msg.getComputations().setPrivate(priv);
        LOGGER.debug("Private: " + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(priv)));

        prepareScalar(msg, scalar);
        prepareScalarLength(msg);

        prepareElement(msg, element);
        prepareElementLength(msg);
    }

    protected void prepareScalar(PWDServerKeyExchangeMessage msg, BigInteger scalar) {
        msg.setScalar(ArrayConverter.bigIntegerToByteArray(scalar));
        LOGGER.debug("Scalar: " + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(scalar)));
    }

    protected void prepareScalarLength(PWDServerKeyExchangeMessage msg) {
        msg.setScalarLength(msg.getScalar().getValue().length);
        LOGGER.debug("ScalarLength: " + msg.getScalarLength());
    }

    protected void prepareElement(PWDServerKeyExchangeMessage msg, ECPoint element) {
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

    protected void prepareElementLength(PWDServerKeyExchangeMessage msg) {
        msg.setElementLength(msg.getElement().getValue().length);
        LOGGER.debug("ElementLength: " + msg.getElementLength());
    }
}
