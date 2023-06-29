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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC draft-ietf-tls-tls13-21 */
public class PreSharedKeyExtensionParser extends ExtensionParser<PreSharedKeyExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ConnectionEndType talkingConnectionEndType;

    public PreSharedKeyExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
        this.talkingConnectionEndType = tlsContext.getTalkingConnectionEndType();
    }

    @Override
    public void parse(PreSharedKeyExtensionMessage msg) {
        LOGGER.debug("Parsing PreSharedKeyExtensionMessage");
        // Client -> Server
        if (talkingConnectionEndType == ConnectionEndType.CLIENT) {
            parsePreSharedKeyIdentityListLength(msg);
            parsePreSharedKeyIdentityListBytes(msg);
            parsePreSharedKeyBinderListLength(msg);
            parsePreSharedKeyBinderListBytes(msg);
        } else {
            // Server -> Client
            parseSelectedIdentity(msg);
        }
    }

    private void parsePreSharedKeyIdentityListLength(PreSharedKeyExtensionMessage msg) {
        msg.setIdentityListLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyIdentityListLength: " + msg.getIdentityListLength().getValue());
    }

    private void parsePreSharedKeyIdentityListBytes(PreSharedKeyExtensionMessage msg) {
        msg.setIdentityListBytes(parseByteArrayField(msg.getIdentityListLength().getValue()));
        LOGGER.debug("Identity list bytes: {}", msg.getIdentityListBytes().getValue());

        List<PSKIdentity> identities = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(msg.getIdentityListBytes().getValue());
        while (innerStream.available() > 0) {
            PSKIdentityParser parser = new PSKIdentityParser(innerStream);
            PSKIdentity identity = new PSKIdentity();
            parser.parse(identity);
            identities.add(identity);
        }
        msg.setIdentities(identities);
    }

    private void parsePreSharedKeyBinderListLength(PreSharedKeyExtensionMessage msg) {
        msg.setBinderListLength(parseIntField(ExtensionByteLength.PSK_BINDER_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyBinderListLength: " + msg.getBinderListLength().getValue());
    }

    private void parsePreSharedKeyBinderListBytes(PreSharedKeyExtensionMessage msg) {
        msg.setBinderListBytes(parseByteArrayField(msg.getBinderListLength().getValue()));
        LOGGER.debug("Binder list bytes: {}", msg.getBinderListBytes().getValue());

        List<PSKBinder> binders = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(msg.getBinderListBytes().getValue());

        while (innerStream.available() > 0) {
            PSKBinderParser parser = new PSKBinderParser(innerStream);
            PSKBinder binder = new PSKBinder();
            parser.parse(binder);
            binders.add(binder);
        }
        msg.setBinders(binders);
    }

    private void parseSelectedIdentity(PreSharedKeyExtensionMessage msg) {
        msg.setSelectedIdentity(parseIntField(ExtensionByteLength.PSK_SELECTED_IDENTITY_LENGTH));
        LOGGER.debug("SelectedIdentity:" + msg.getSelectedIdentity().getValue());
    }
}
