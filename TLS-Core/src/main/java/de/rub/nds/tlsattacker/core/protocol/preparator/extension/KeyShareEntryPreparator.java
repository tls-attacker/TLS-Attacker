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
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        EllipticCurve curve = CurveFactory.getCurve(entry.getGroupConfig());
        Point passwordElement = PWDComputations.computePasswordElement(chooser, curve);
        PWDComputations.PWDKeyMaterial keyMaterial = PWDComputations.generateKeyMaterial(curve, passwordElement,
                chooser);
        int curveSize = curve.getModulus().bitLength() / 8;
        entry.setPrivateKey(keyMaterial.privateKeyScalar);
        byte[] serializedScalar = ArrayConverter.bigIntegerToByteArray(keyMaterial.scalar);
        entry.setPublicKey(ArrayConverter.concatenate(
                ArrayConverter.bigIntegerToByteArray(keyMaterial.element.getX().getData(), curveSize, true),
                ArrayConverter.bigIntegerToByteArray(keyMaterial.element.getY().getData(), curveSize, true),
                ArrayConverter.intToBytes(serializedScalar.length, 1), serializedScalar));
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(entry.getPublicKey().getValue()));
        LOGGER.debug("PasswordElement.x: "
                + ArrayConverter.bytesToHexString(ArrayConverter
                        .bigIntegerToByteArray(passwordElement.getX().getData())));
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
            Point ecPublicKey = KeyShareCalculator.createPublicKey(entry.getGroupConfig(), entry.getPrivateKey());
            // TODO We currently just use the default point format
            byte[] serializedPoint = PointFormatter.formatToByteArray(ecPublicKey, chooser.getConfig()
                    .getDefaultSelectedPointFormat());
            entry.setPublicKey(serializedPoint);
        } else if (entry.getGroupConfig().isCurve() && !entry.getGroupConfig().isStandardCurve()) {
            byte[] publicKey = KeyShareCalculator.createMontgomeryKeyShare(entry.getGroupConfig(),
                    entry.getPrivateKey());
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
