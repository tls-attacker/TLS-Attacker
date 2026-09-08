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
import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.protocol.exception.PreparationException;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.computations.PWDComputations;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareStoreEntry;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.List;
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

    private void prepareKeyShare() {
        if (entry.getGroupConfig().isPQGroup()) {
            preparePQKeyShare();
        } else if (entry.getGroupConfig().isHybridPQGroup()) {
            prepareHybridPQKeyShare();
        } else {
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
                    KeyShareCalculator.createKeyAgreementPublicKey(
                            entry.getGroupConfig(),
                            entry.getPrivateKey(),
                            chooser.getConfig().getDefaultSelectedPointFormat());
            entry.setPublicKey(serializedPoint);

            LOGGER.debug("KeyShare: {}", entry.getPublicKey().getValue());
        }
    }

    private void preparePQKeyShare() {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            KeyShareCalculator.createMLKEMKeyShare(
                    entry.getGroupConfig(),
                    entry,
                    chooser.getContext().getTlsContext().getBadSecureRandom());
            byte[] defaultMLKEMPublicKey = chooser.getConfig().getDefaultClientMLKEMPublicKey();
            if (defaultMLKEMPublicKey != null && defaultMLKEMPublicKey.length > 0) {
                LOGGER.debug("Using defaultClientMLKEMPublicKey from config");
                entry.setPublicKey(defaultMLKEMPublicKey);
            } else {
                entry.setPublicKey(entry.getMLKEMPublicKey().getValue());
            }
            chooser.getContext()
                    .getTlsContext()
                    .getClientMLKEMPublicKeys()
                    .put(entry.getGroupConfig(), entry.getMLKEMPublicKeyContainer());
            chooser.getContext()
                    .getTlsContext()
                    .getClientMLKEMPrivateKeys()
                    .put(entry.getGroupConfig(), entry.getMLKEMPrivateKeyContainer());
            LOGGER.debug("Generated Client PQ KeyPair for group: {}", entry.getGroupConfig());
        } else {
            // The Server does not generate an own keypair for post-quantum groups,
            // but encapsulates the shared secret using the Client's public key share.
            byte[] clientPublicKey = getClientKeySharePublicKey(entry.getGroupConfig());

            if (clientPublicKey == null) {
                throw new PreparationException(
                        "Cannot prepare Server KeyShare: Client public key for group "
                                + entry.getGroupConfig()
                                + " is missing from the context.");
            }

            MlKemEncapsulation result =
                    KeyShareCalculator.mlkemEncaps(
                            entry.getGroupConfig(),
                            clientPublicKey,
                            chooser.getContext().getTlsContext().getBadSecureRandom());
            byte[] defaultMLKEMCiphertext = chooser.getConfig().getDefaultServerMLKEMCiphertext();
            if (defaultMLKEMCiphertext != null && defaultMLKEMCiphertext.length > 0) {
                LOGGER.debug("Using defaultServerMLKEMCiphertext from config");
                entry.setPublicKey(defaultMLKEMCiphertext);
            } else {
                entry.setPublicKey(result.getCiphertext());
            }
            chooser.getContext().getTlsContext().setPQSharedSecret(result.getSharedSecret());
            chooser.getContext()
                    .getTlsContext()
                    .setServerMLKEMCiphertext(entry.getPublicKey().getValue());

            LOGGER.debug("Encapsulated PQ secret for group: {}", entry.getGroupConfig());
        }
    }

    private void prepareHybridPQKeyShare() {
        LOGGER.debug("Generating Hybrid PQ Keyshare for group: {}", entry.getGroupConfig());
        NamedGroup classicalGroup = entry.getGroupConfig().getHybridPostQuantumClassicNamedGroup();
        NamedGroup pqGroup = entry.getGroupConfig().getHybridPostQuantumNamedGroup();

        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            // In the case of a hybrid pq group the client must handle two separate
            // keyshares; One for the classical and one for the pq component.
            if (entry.getPrivateKey() == null) {
                entry.setPrivateKey(chooser.getClientEphemeralEcPrivateKey());
            }
            byte[] classicalPublicKey =
                    KeyShareCalculator.createKeyAgreementPublicKey(
                            classicalGroup,
                            entry.getPrivateKey(),
                            chooser.getConfig().getDefaultSelectedPointFormat());

            KeyShareCalculator.createMLKEMKeyShare(
                    pqGroup, entry, chooser.getContext().getTlsContext().getBadSecureRandom());

            byte[] pqPublicKey = entry.getMLKEMPublicKey().getValue();
            byte[] defaultMLKEMPublicKey = chooser.getConfig().getDefaultClientMLKEMPublicKey();
            if (defaultMLKEMPublicKey != null && defaultMLKEMPublicKey.length > 0) {
                LOGGER.debug("Using defaultClientMLKEMPublicKey from config for hybrid KEX");
                pqPublicKey = defaultMLKEMPublicKey;
            }

            LOGGER.debug(
                    "Setting Client MLKEM public key to {}",
                    entry.getMLKEMPublicKeyContainer().getEncapsulationKey());
            chooser.getContext()
                    .getTlsContext()
                    .getClientMLKEMPublicKeys()
                    .put(entry.getGroupConfig(), entry.getMLKEMPublicKeyContainer());

            LOGGER.debug(
                    "Setting Client MLKEM private key to {}",
                    entry.getMLKEMPrivateKeyContainer().getDecapsulationKey());

            chooser.getContext()
                    .getTlsContext()
                    .getClientMLKEMPrivateKeys()
                    .put(entry.getGroupConfig(), entry.getMLKEMPrivateKeyContainer());

            entry.setPublicKey(
                    PQUtils.concatenateHybridKeyShare(
                            entry.getGroupConfig(), classicalPublicKey, pqPublicKey));

            LOGGER.debug(
                    "Generated Client Hybrid PQ KeyShare: {}", entry.getPublicKey().getValue());
        } else {
            if (entry.getPrivateKey() == null) {
                entry.setPrivateKey(chooser.getServerEphemeralEcPrivateKey());
            }
            byte[] classicalPublicKey =
                    KeyShareCalculator.createKeyAgreementPublicKey(
                            classicalGroup,
                            entry.getPrivateKey(),
                            chooser.getConfig().getDefaultSelectedPointFormat());

            byte[][] splitClientKeyShare =
                    PQUtils.splitKeyShare(
                            entry.getGroupConfig(),
                            ConnectionEndType.CLIENT,
                            getClientKeySharePublicKey(entry.getGroupConfig()));

            // Use Client public key share to compute encapsulation algorithm
            byte[] clientPQPublicKey = splitClientKeyShare[1];
            MlKemEncapsulation encapsulationResult =
                    KeyShareCalculator.mlkemEncaps(
                            entry.getGroupConfig(),
                            clientPQPublicKey,
                            chooser.getContext().getTlsContext().getBadSecureRandom());

            byte[] pqCiphertext = encapsulationResult.getCiphertext();
            byte[] defaultMLKEMCiphertext = chooser.getConfig().getDefaultServerMLKEMCiphertext();
            if (defaultMLKEMCiphertext != null && defaultMLKEMCiphertext.length > 0) {
                LOGGER.debug("Using defaultServerMLKEMCiphertext from config for hybrid KEX");
                pqCiphertext = defaultMLKEMCiphertext;
            }

            chooser.getContext()
                    .getTlsContext()
                    .setPQSharedSecret(encapsulationResult.getSharedSecret());
            chooser.getContext().getTlsContext().setServerMLKEMCiphertext(pqCiphertext);

            entry.setPublicKey(
                    PQUtils.concatenateHybridKeyShare(
                            entry.getGroupConfig(), classicalPublicKey, pqCiphertext));
            LOGGER.debug("Generated Server Hybrid PQ KeyShare for {}", entry.getGroupConfig());
        }
    }

    private byte[] getClientKeySharePublicKey(NamedGroup group) {
        List<KeyShareStoreEntry> clientKeyShareEntryList =
                chooser.getContext().getTlsContext().getClientKeyShareStoreEntryList();
        if (clientKeyShareEntryList != null) {
            for (KeyShareStoreEntry entry : clientKeyShareEntryList) {
                if (entry.getGroup() == group) {
                    return entry.getPublicKey();
                }
            }
        }

        // If no matching KeyShare is found, return null.
        // Our KeyShareEntryPreparator will safely catch this and throw a PreparationException.
        return null;
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
