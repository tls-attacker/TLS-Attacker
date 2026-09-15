/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.key.MlKemPublicKey;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareEntryParser extends Parser<KeyShareEntry> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final boolean helloRetryRequestForm;

    /**
     * The end type that issued the key share. ML-KEM key shares of one group have a different
     * meaning and length depending on the issuer: the client sends an encapsulation key, the server
     * sends a ciphertext.
     */
    private final ConnectionEndType issuerEndType;

    public KeyShareEntryParser(
            InputStream stream, boolean helloRetryRequestForm, ConnectionEndType issuerEndType) {
        super(stream);
        this.helloRetryRequestForm = helloRetryRequestForm;
        this.issuerEndType = issuerEndType;
    }

    @Override
    public void parse(KeyShareEntry entry) {
        LOGGER.debug("Parsing KeyShareEntry");
        parseKeyShareGroup(entry);
        entry.setGroupConfig(NamedGroup.getNamedGroup(entry.getGroup().getValue()));
        if (!helloRetryRequestForm) {
            parseKeyShareLength(entry);
            parseKeyShare(entry);
        }
    }

    /** Reads the next bytes as the keyShareType of the Extension and writes them in the message */
    private void parseKeyShareGroup(KeyShareEntry pair) {
        pair.setGroup(parseByteArrayField(ExtensionByteLength.KEY_SHARE_GROUP));
        LOGGER.debug("KeyShareGroup: {}", pair.getGroup().getValue());
    }

    /**
     * Reads the next bytes as the keyShareLength of the Extension and writes them in the message
     */
    private void parseKeyShareLength(KeyShareEntry pair) {
        pair.setPublicKeyLength(parseIntField(ExtensionByteLength.KEY_SHARE_LENGTH));
        LOGGER.debug("KeyShareLength: {}", pair.getPublicKeyLength().getValue());
    }

    /** Reads the next bytes as the keyShare of the Extension and writes them in the message */
    private void parseKeyShare(KeyShareEntry pair) {
        pair.setPublicKey(parseByteArrayField(pair.getPublicKeyLength().getValue()));
        LOGGER.debug("KeyShare: {}", pair.getPublicKey().getValue());
        NamedGroup group = pair.getGroupConfig();
        if (group == null) {
            LOGGER.debug("Unknown NamedGroup - not splitting the KeyShare into its components");
        } else if (group.isMlKemGroup()) {
            parseMlKemComponents(pair, group);
        } else if (group.isEcGroup() || group.isDhGroup()) {
            pair.setDhPublicKey(pair.getPublicKey().getValue());
            LOGGER.debug("(EC)DH Public Key: {}", pair.getDhPublicKey().getValue());
        } else {
            LOGGER.debug(
                    "NamedGroup {} carries no key share components that can be extracted", group);
        }
    }

    /**
     * Splits a (hybrid) ML-KEM key share into its components and writes them into the dedicated
     * fields of the entry. A client key share carries an encapsulation key, a server key share
     * carries a ciphertext.
     */
    private void parseMlKemComponents(KeyShareEntry pair, NamedGroup group) {
        int expectedLength = getExpectedMlKemKeyShareLength(group);
        if (pair.getPublicKeyLength().getValue() != expectedLength) {
            LOGGER.warn(
                    "KeyShare of {} has length {} but {} was expected for a key share of the {} - not splitting the KeyShare into its components",
                    group,
                    pair.getPublicKeyLength().getValue(),
                    expectedLength,
                    issuerEndType);
            return;
        }

        byte[] pqBytes;
        if (group.isHybridPQGroup()) {
            byte[][] keyShares =
                    PQUtils.splitKeyShare(group, issuerEndType, pair.getPublicKey().getValue());
            pair.setDhPublicKey(keyShares[0]);
            pqBytes = keyShares[1];
            LOGGER.debug("Hybrid (EC)DH Public Key: {}", pair.getDhPublicKey().getValue());
        } else {
            pqBytes = pair.getPublicKey().getValue();
        }

        if (issuerEndType == ConnectionEndType.CLIENT) {
            MlKemParameters parameters =
                    (MlKemParameters) group.getAnyInvolvedPqGroup().getAsymmetricParameters();
            pair.setMlKemPublicKey(new MlKemPublicKey(parameters, pqBytes));
            LOGGER.debug("ML-KEM Encapsulation Key: {}", pair.getMlKemPublicKey().getValue());
        } else {
            pair.setMlKemCiphertext(pqBytes);
            LOGGER.debug("ML-KEM Ciphertext: {}", pair.getMlKemCiphertext().getValue());
        }
    }

    private int getExpectedMlKemKeyShareLength(NamedGroup group) {
        int expectedLength = PQUtils.getPQKeyShareLength(group, issuerEndType);
        if (group.isHybridPQGroup()) {
            expectedLength += PQUtils.getEcPublicKeyLength(group);
        }
        return expectedLength;
    }
}
