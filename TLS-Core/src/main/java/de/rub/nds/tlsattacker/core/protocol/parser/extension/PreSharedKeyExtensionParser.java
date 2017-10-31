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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import java.util.LinkedList;
import java.util.List;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionParser extends ExtensionParser<PreSharedKeyExtensionMessage> {
    
    public PreSharedKeyExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PreSharedKeyExtensionMessage msg) {
        LOGGER.debug("Parsing PreSharedKeyExtensionMessage");
        parsePreSharedKeyIdentitiyListLength(msg);
        parsePreSharedKeyIdentityListBytes(msg);
        parsePreSharedKeyBinderListLength(msg);
        parsePreSharedKeyBinderListBytes(msg);
    }

    @Override
    protected PreSharedKeyExtensionMessage createExtensionMessage() {
        return new PreSharedKeyExtensionMessage();
    }
    
    private void parsePreSharedKeyIdentitiyListLength(PreSharedKeyExtensionMessage msg)
    {
        msg.setIdentityListLength(parseIntField(ExtensionByteLength.PSK_IDENTITY_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyIdentityListLength: " + msg.getIdentityListLength());
    }
    
    private void parsePreSharedKeyIdentityListBytes(PreSharedKeyExtensionMessage msg)
    {
        byte[] pskIdentityListBytes = parseByteArrayField(msg.getIdentityListLength());
        LOGGER.debug("PreSharedKeyIdentityListBytes: " + ArrayConverter.bytesToHexString(pskIdentityListBytes));
        
        int parsed = 0;
        List<PSKIdentity> identities = new LinkedList<>();
        while (parsed < msg.getIdentityListLength()) 
        {
            int length = parseIntField(ExtensionByteLength.PSK_IDENTITY_LENGTH);
            byte[] identityBytes = parseByteArrayField(length);
            byte[] obfuscatedTicketAgeBytes = parseByteArrayField(ExtensionByteLength.TICKET_AGE_LENGTH);
            
            PSKIdentity pskIdentity = new PSKIdentity(identityBytes, obfuscatedTicketAgeBytes);
            identities.add(pskIdentity);
            parsed += ExtensionByteLength.PSK_IDENTITY_LENGTH + length + ExtensionByteLength.TICKET_AGE_LENGTH;
        }
        
        msg.setIdentities(identities);
    }
    
    private void parsePreSharedKeyBinderListLength(PreSharedKeyExtensionMessage msg)
    {
        msg.setBinderListLength(parseIntField(ExtensionByteLength.PSK_BINDER_LIST_LENGTH));
        LOGGER.debug("PreSharedKeyBinderListLength: " + msg.getBinderListLength());
    }
    
    private void parsePreSharedKeyBinderListBytes(PreSharedKeyExtensionMessage msg)
    {
        byte[] pskBinderListBytes = parseByteArrayField(msg.getBinderListLength());
        LOGGER.debug("PreSharedKeyBinderListBytes: " + ArrayConverter.bytesToHexString(pskBinderListBytes));
        
        int parsed = 0;
        List<PSKBinder> binders = new LinkedList<>();
        while (parsed < msg.getIdentityListLength()) 
        {
            int length = parseIntField(ExtensionByteLength.PSK_BINDER_LENGTH);
            byte[] binderBytes = parseByteArrayField(length);
            
            PSKBinder pskBinder = new PSKBinder(binderBytes);
            binders.add(pskBinder);
            parsed += ExtensionByteLength.PSK_BINDER_LENGTH + length;
        }
        
        msg.setBinders(binders);
    }

}
