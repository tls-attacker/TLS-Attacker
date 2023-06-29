/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.EarlyDataExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EarlyDataExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EarlyDataExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EarlyDataExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** RFC draft-ietf-tls-tls13-21 */
@XmlRootElement(name = "EarlyDataExtension")
public class EarlyDataExtensionMessage extends ExtensionMessage<EarlyDataExtensionMessage> {

    private ModifiableInteger maxEarlyDataSize;

    private boolean newSessionTicketExtension = false;

    public EarlyDataExtensionMessage() {
        super(ExtensionType.EARLY_DATA);
    }

    public EarlyDataExtensionMessage(boolean newSessionTicketExtension) {
        super(ExtensionType.EARLY_DATA);
        this.newSessionTicketExtension = newSessionTicketExtension;
    }

    /**
     * @return the max_early_data_size
     */
    public ModifiableInteger getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }

    /**
     * @param maxEarlyDataSize the maxEarlyDataSize to set
     */
    public void setMaxEarlyDataSize(ModifiableInteger maxEarlyDataSize) {
        this.maxEarlyDataSize = maxEarlyDataSize;
    }

    public void setMaxEarlyDataSize(int maxEarlyDataSize) {
        this.maxEarlyDataSize =
                ModifiableVariableFactory.safelySetValue(this.maxEarlyDataSize, maxEarlyDataSize);
    }

    public boolean isNewSessionTicketExtension() {
        return newSessionTicketExtension;
    }

    public void setNewSessionTicketExtension(boolean newSessionTicketExtension) {
        this.newSessionTicketExtension = newSessionTicketExtension;
    }

    @Override
    public EarlyDataExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EarlyDataExtensionParser(stream, tlsContext);
    }

    @Override
    public EarlyDataExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new EarlyDataExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EarlyDataExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new EarlyDataExtensionSerializer(this);
    }

    @Override
    public EarlyDataExtensionHandler getHandler(TlsContext tlsContext) {
        return new EarlyDataExtensionHandler(tlsContext);
    }
}
