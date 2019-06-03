/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class KeyShareEntryPreparator extends Preparator<KeyShareEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final KeyShareEntry entry;

    public KeyShareEntryPreparator(Chooser chooser, KeyShareEntry entry) {
        super(chooser, entry);
        this.entry = entry;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing KeySharePairExtension");
        if (chooser.getSelectedCipherSuite().isPWD()) {
            try {
                preparePWDKeyShare();
            } catch (CryptoException e) {
                throw new PreparationException("Failed to generate password element", e);
            }
        } else {
            prepareKeyShare();
        }

        prepareKeyShareType();
        prepareKeyShareLength();
    }

    private void preparePWDKeyShare() throws CryptoException {
        ECCurve curve = ECNamedCurveTable.getParameterSpec(entry.getGroupConfig().getJavaName()).getCurve();
        ECPoint passwordElement = PWDComputations.computePasswordElement(chooser, curve);
        PWDComputations.PWDKeyMaterial keyMaterial = PWDComputations.generateKeyMaterial(curve, passwordElement,
                chooser);
        int curveSize = curve.getFieldSize() / 8;
        entry.setPrivateKey(keyMaterial.priv);
        byte[] serializedScalar = ArrayConverter.bigIntegerToByteArray(keyMaterial.scalar);
        entry.setPublicKey(ArrayConverter.concatenate(
                ArrayConverter.bigIntegerToByteArray(keyMaterial.element.getXCoord().toBigInteger(), curveSize, true),
                ArrayConverter.bigIntegerToByteArray(keyMaterial.element.getYCoord().toBigInteger(), curveSize, true),
                ArrayConverter.intToBytes(serializedScalar.length, 1), serializedScalar));
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(entry.getPublicKey().getValue()));
        LOGGER.debug("PasswordElement.x: "
                + ArrayConverter.bytesToHexString(ArrayConverter.bigIntegerToByteArray(passwordElement.getXCoord()
                        .toBigInteger())));
    }

    private void prepareKeyShare() {
        if (entry.getPrivateKey() == null) {
            if (chooser.getConnectionEndType().equals(ConnectionEndType.CLIENT)) {
                entry.setPrivateKey(chooser.getClientEcPrivateKey());
            }
            if (chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)) {
                entry.setPrivateKey(chooser.getServerEcPrivateKey());
            }
        }
        if (entry.getGroupConfig().isStandardCurve()) {
            ECPoint ecPublicKey = KeyShareCalculator
                    .createClassicEcPoint(entry.getGroupConfig(), entry.getPrivateKey());
            List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            byte[] serializedPoint;
            try {
                serializedPoint = ECCUtilsBCWrapper.serializeECPoint(formatArray, ecPublicKey);
            } catch (IOException ex) {
                throw new PreparationException("Could not serialize clientPublicKey", ex);
            }
            entry.setPublicKey(serializedPoint);
        } else if (entry.getGroupConfig().isCurve() && !entry.getGroupConfig().isStandardCurve()) {
            byte[] publicKey = KeyShareCalculator.createX25519KeyShare(entry.getGroupConfig(), entry.getPrivateKey());
            entry.setPublicKey(publicKey);
        } else {
            throw new UnsupportedOperationException("The group \"" + entry.getGroupConfig().name()
                    + "\" is not supported yet");
        }
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(entry.getPublicKey().getValue()));
    }

    private void prepareKeyShareType() {
        entry.setGroup(entry.getGroupConfig().getValue());
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(entry.getGroup().getValue()));
    }

    private void prepareKeyShareLength() {
        entry.setPublicKeyLength(entry.getPublicKey().getValue().length);
        LOGGER.debug("KeyShareLength: " + entry.getPublicKeyLength().getValue());
    }

}
