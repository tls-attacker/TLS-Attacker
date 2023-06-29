/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareEntryParser extends Parser<KeyShareEntry> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final boolean helloRetryRequestForm;

    public KeyShareEntryParser(InputStream stream, boolean helloRetryRequestForm) {
        super(stream);
        this.helloRetryRequestForm = helloRetryRequestForm;
    }

    @Override
    public void parse(KeyShareEntry entry) {
        LOGGER.debug("Parsing KeyShareEntry");
        parseKeyShareGroup(entry);
        if (!helloRetryRequestForm) {
            parseKeyShareLength(entry);
            parseKeyShare(entry);
        }
        entry.setGroupConfig(NamedGroup.getNamedGroup(entry.getGroup().getValue()));
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
        LOGGER.debug("KeyShareLength: " + pair.getPublicKeyLength().getValue());
    }

    /** Reads the next bytes as the keyShare of the Extension and writes them in the message */
    private void parseKeyShare(KeyShareEntry pair) {
        pair.setPublicKey(parseByteArrayField(pair.getPublicKeyLength().getValue()));
        LOGGER.debug("KeyShare: {}", pair.getPublicKey().getValue());
    }
}
