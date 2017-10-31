/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionSerializer extends ExtensionSerializer<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    
    public PreSharedKeyExtensionSerializer(PreSharedKeyExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing PreSharedKeyExtensionMessage");
        
        appendInt(msg.getIdentityListLength(), ExtensionByteLength.PSK_IDENTITY_LIST_LENGTH);
        LOGGER.debug("PreSharedKeyIdentityListLength: " + msg.getIdentityListLength());
        writeIdentities();
        
        appendInt(msg.getBinderListLength(), ExtensionByteLength.PSK_BINDER_LIST_LENGTH);
        LOGGER.debug("PreSharedKeyBinderListLength: " + msg.getBinderListLength());
        writeBinders();
        return getAlreadySerialized();
    }
    
    public void writeIdentities()
    {
        for(PSKIdentity pskIdentity : msg.getIdentities())
        {
            appendInt(pskIdentity.getIdentityLength(), ExtensionByteLength.PSK_IDENTITY_LENGTH);
            appendBytes(pskIdentity.getIdentity());
            appendBytes(pskIdentity.getObfuscatedTicketAge());
        }
    }
    
    public void writeBinders()
    {
        for(PSKBinder pskBinder : msg.getBinders())
        {
            appendInt(pskBinder.getBinderEntryLength(), ExtensionByteLength.PSK_BINDER_LENGTH);
            appendBytes(pskBinder.getBinderEntry());
        }
    }
    

}
