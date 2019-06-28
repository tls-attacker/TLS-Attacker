/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PreSharedKeyExtensionParser extends ExtensionParser<PreSharedKeyExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PreSharedKeyExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PreSharedKeyExtensionMessage msg) {
        LOGGER.debug("Parsing PreSharedKeyExtensionMessage");
        if (super.getBytesLeft() > 2) // Client -> Server
        {
            parsePreSharedKeyIdentitiyListLength(msg);
            parsePreSharedKeyIdentityListBytes(msg);
            parsePreSharedKeyBinderListLength(msg);
            parsePreSharedKeyBinderListBytes(msg);
        } else // Server -> Client
        {
            parseSelectedIdentity(msg);
        }
    }

    @Override
    protected PreSharedKeyExtensionMessage createExtensionMessage() {
        return new PreSharedKeyExtensionMessage();
    }

    private void parsePreSharedKeyIdentitiyListLength(PreSharedKeyExtensionMessage msg) {
        msg.setIdentityListLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyIdentityListLength: " + msg.getIdentityListLength().getValue());
    }

    private void parsePreSharedKeyIdentityListBytes(PreSharedKeyExtensionMessage msg) {
        msg.setIdentityListBytes(parseByteArrayField(msg.getIdentityListLength().getValue()));
        LOGGER.debug("Identity list bytes: " + ArrayConverter.bytesToHexString(msg.getIdentityListBytes().getValue()));

        List<PSKIdentity> identities = new LinkedList<>();
        int parsed = 0;
        while (parsed < msg.getIdentityListLength().getValue()) {
            PSKIdentityParser parser = new PSKIdentityParser(parsed, msg.getIdentityListBytes().getValue());
            identities.add(parser.parse());
            parsed = parser.getPointer();
        }
        msg.setIdentities(identities);
    }

    private void parsePreSharedKeyBinderListLength(PreSharedKeyExtensionMessage msg) {
        msg.setBinderListLength(parseIntField(ExtensionByteLength.PSK_BINDER_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyBinderListLength: " + msg.getBinderListLength().getValue());
    }

    private void parsePreSharedKeyBinderListBytes(PreSharedKeyExtensionMessage msg) {
        msg.setBinderListBytes(parseByteArrayField(msg.getBinderListLength().getValue()));
        LOGGER.debug("Binder list bytes: " + ArrayConverter.bytesToHexString(msg.getBinderListBytes().getValue()));

        List<PSKBinder> binders = new LinkedList<>();
        int parsed = 0;
        while (parsed < msg.getBinderListLength().getValue()) {
            PSKBinderParser parser = new PSKBinderParser(parsed, msg.getBinderListBytes().getValue());
            binders.add(parser.parse());
            parsed = parser.getPointer();
        }
        msg.setBinders(binders);
    }

    private void parseSelectedIdentity(PreSharedKeyExtensionMessage msg) {
        msg.setSelectedIdentity(parseIntField(ExtensionByteLength.PSK_SELECTED_IDENTITY_LENGTH));
        LOGGER.debug("SelectedIdentity:" + msg.getSelectedIdentity().getValue());
    }

}
