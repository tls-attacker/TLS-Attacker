/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKBinder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSK.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.LinkedList;
import java.util.List;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionPreparator extends ExtensionPreparator<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    
    public PreSharedKeyExtensionPreparator(Chooser chooser, PreSharedKeyExtensionMessage message,
            ExtensionSerializer<PreSharedKeyExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PreSharedKeyExtensionMessage");
        prepareLists();
        msg.setIdentityListLength(msg.getIdentities().size());
        msg.setBinderListLength(msg.getBinders().size());
    }
    
    private void prepareLists()
    {
        List<PSKIdentity> identities = new LinkedList<>();
        List<PSKBinder> binders = new LinkedList<>();
        //TODO multiple Identities
        PSKIdentity pskIdentity = new PSKIdentity(chooser.getConfig().getPreSharedKeyIdentity(), chooser.getConfig().getTicketAgeAdd());
        PSKBinder pskBinder = new PSKBinder(chooser.getConfig().getPreSharedKeyBinder());
        
        identities.add(pskIdentity);
        binders.add(pskBinder);
        
        msg.setIdentities(identities);
        msg.setBinders(binders);
    }

}
