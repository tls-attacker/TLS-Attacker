/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * RFC draft-ietf-tls-tls13-21
 */
@XmlRootElement(name = "EarlyDataExtension")
public class EarlyDataExtensionMessage extends ExtensionMessage {

    private ModifiableInteger maxEarlyDataSize;

    private boolean newSessionTicketExtension = false;

    public EarlyDataExtensionMessage() {
        super(ExtensionType.EARLY_DATA);
    }

    public EarlyDataExtensionMessage(boolean newSessionTicketExtension) {
        super(ExtensionType.EARLY_DATA);
        this.newSessionTicketExtension = newSessionTicketExtension;
    }

    public EarlyDataExtensionMessage(Config config) {
        super(ExtensionType.EARLY_DATA);
    }

    /**
     * @return the max_early_data_size
     */
    public ModifiableInteger getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }

    /**
     * @param maxEarlyDataSize
     *                         the maxEarlyDataSize to set
     */
    public void setMaxEarlyDataSize(ModifiableInteger maxEarlyDataSize) {
        this.maxEarlyDataSize = maxEarlyDataSize;
    }

    public void setMaxEarlyDataSize(int maxEarlyDataSize) {
        this.maxEarlyDataSize = ModifiableVariableFactory.safelySetValue(this.maxEarlyDataSize, maxEarlyDataSize);
    }

    public boolean isNewSessionTicketExtension() {
        return newSessionTicketExtension;
    }

    public void setNewSessionTicketExtension(boolean newSessionTicketExtension) {
        this.newSessionTicketExtension = newSessionTicketExtension;
    }
}
