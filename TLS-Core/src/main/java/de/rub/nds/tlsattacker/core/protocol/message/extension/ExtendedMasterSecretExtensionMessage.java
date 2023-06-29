/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedMasterSecretExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This is the extended_master_secret message.
 *
 * <p>There is no need for any data, the presence of this extension is enough.
 *
 * <p>This extension is defined in RFC7627
 */
@XmlRootElement(name = "ExtendedMasterSecretExtension")
public class ExtendedMasterSecretExtensionMessage
        extends ExtensionMessage<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionMessage() {
        super(ExtensionType.EXTENDED_MASTER_SECRET);
    }

    @Override
    public ExtendedMasterSecretExtensionParser getParser(
            TlsContext tlsContext, InputStream stream) {
        return new ExtendedMasterSecretExtensionParser(stream, tlsContext);
    }

    @Override
    public ExtendedMasterSecretExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ExtendedMasterSecretExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ExtendedMasterSecretExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ExtendedMasterSecretExtensionSerializer(this);
    }

    @Override
    public ExtendedMasterSecretExtensionHandler getHandler(TlsContext tlsContext) {
        return new ExtendedMasterSecretExtensionHandler(tlsContext);
    }
}
