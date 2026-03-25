/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

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
        LOGGER.debug("Using curve: {}", entry.getGroupConfig());
        CyclicGroup<?> group = entry.getGroupConfig().getGroupParameters().getGroup();
        Point passwordElement = PWDComputations.computePasswordElement(chooser, group);
        PWDComputations.PWDKeyMaterial keyMaterial =
                PWDComputations.generateKeyMaterial(group, passwordElement, chooser);
        entry.setPrivateKey(keyMaterial.privateKeyScalar);
        byte[] serializedScalar = DataConverter.bigIntegerToByteArray(keyMaterial.scalar);
        entry.setPublicKey(
                DataConverter.concatenate(
                        PointFormatter.toRawFormat(keyMaterial.element),
                        DataConverter.intToBytes(serializedScalar.length, 1),
                        serializedScalar));
        LOGGER.debug("KeyShare: {}", entry.getPublicKey().getValue());
        LOGGER.debug(
                "PasswordElement.x: {}",
                DataConverter.bigIntegerToByteArray(passwordElement.getFieldX().getData()));
    }

    private void prepareMLKEMKeyShare() {
        LOGGER.debug("Using group: {}", entry.getGroupConfig());
        MLKEMParameters params = PQUtils.getMLKEMParameters(entry.getGroupConfig());
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        SecureRandom random = chooser.getContext().getTlsContext().getBadSecureRandom();
        generator.init(new MLKEMKeyGenerationParameters(random, params));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        MLKEMPublicKeyParameters pub = (MLKEMPublicKeyParameters) pair.getPublic();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) pair.getPrivate();
        entry.setMLKEMPublicKey(pub);
        entry.setMLKEMPrivateKey(priv);
        entry.setPublicKey(pub.getEncoded());
        LOGGER.debug("KeyShare: {}", entry.getPublicKey().getValue());
    }

    private void prepareKeyShare() {
        if (entry.getGroupConfig().isPQGroup()) {
            if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
                prepareMLKEMKeyShare();
                chooser.getContext()
                        .getTlsContext()
                        .setClientMLKEMPublicKey(entry.getMLKEMPublicKey());
                chooser.getContext()
                        .getTlsContext()
                        .setClientMLKEMPrivateKey(entry.getMLKEMPrivateKey());
                LOGGER.info("Generated Client PQ KeyPair for group: {}", entry.getGroupConfig());
            } else {
                // The Server does not generate an own keypair for post-quantum groups,
                // but encapsulates the shared secret using the Client's public key share.
                byte[] clientPublicKeyBytes =
                        chooser.getClientKeySharePublicKey(entry.getGroupConfig());

                if (clientPublicKeyBytes == null) {
                    throw new PreparationException(
                            "Cannot prepare Server KeyShare: Client public key for group "
                                    + entry.getGroupConfig()
                                    + " is missing from the context.");
                }

                SecretWithEncapsulation result =
                        KeyShareCalculator.mlkemEncaps(
                                entry.getGroupConfig(),
                                clientPublicKeyBytes,
                                chooser.getContext().getTlsContext().getBadSecureRandom());
                entry.setPublicKey(result.getEncapsulation());
                chooser.getContext().getTlsContext().setPQSharedSecret(result.getSecret());

                LOGGER.info("Encapsulated PQ secret for group: {}", entry.getGroupConfig());
            }
        } else { // TODO: Hybrid PQ groups
            // STANDARD ECC LOGIC
            if (entry.getPrivateKey() == null) {
                if (chooser.getConnectionEndType().equals(ConnectionEndType.CLIENT)) {
                    entry.setPrivateKey(chooser.getClientEphemeralEcPrivateKey());
                }
                if (chooser.getConnectionEndType().equals(ConnectionEndType.SERVER)) {
                    entry.setPrivateKey(chooser.getServerEphemeralEcPrivateKey());
                }
            }
            byte[] serializedPoint =
                    KeyShareCalculator.createPublicKey(
                            entry.getGroupConfig(),
                            entry.getPrivateKey(),
                            chooser.getConfig().getDefaultSelectedPointFormat());
            entry.setPublicKey(serializedPoint);

            LOGGER.debug("KeyShare: {}", entry.getPublicKey().getValue());
        }
    }

    private void prepareKeyShareType() {
        entry.setGroup(entry.getGroupConfig().getValue());
        LOGGER.debug("KeyShareType: {}", entry.getGroup().getValue());
    }

    private void prepareKeyShareLength() {
        entry.setPublicKeyLength(entry.getPublicKey().getValue().length);
        LOGGER.debug("KeyShareLength: {}", entry.getPublicKeyLength().getValue());
    }
}
