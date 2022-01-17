/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtendedMasterSecretExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedMasterSecretExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializer;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This is the extended_master_secret message.
 *
 * There is no need for any data, the presence of this extension is enough.
 *
 * This extension is defined in RFC7627
 */
@XmlRootElement(name = "ExtendedMasterSecretExtension")
public class ExtendedMasterSecretExtensionMessage extends ExtensionMessage<ExtendedMasterSecretExtensionMessage> {

    public ExtendedMasterSecretExtensionMessage() {
        super(ExtensionType.EXTENDED_MASTER_SECRET);
    }

    public ExtendedMasterSecretExtensionMessage(Config config) {
        super(ExtensionType.EXTENDED_MASTER_SECRET);
    }

    @Override
    public ExtendedMasterSecretExtensionParser getParser(TlsContext context, InputStream stream) {
        return new ExtendedMasterSecretExtensionParser(stream, context.getConfig());
    }

    @Override
    public ExtendedMasterSecretExtensionPreparator getPreparator(TlsContext context) {
        return new ExtendedMasterSecretExtensionPreparator(context.getChooser(), this, getSerializer(context));
    }

    @Override
    public ExtendedMasterSecretExtensionSerializer getSerializer(TlsContext context) {
        return new ExtendedMasterSecretExtensionSerializer(this);
    }

    @Override
    public ExtendedMasterSecretExtensionHandler getHandler(TlsContext context) {
        return new ExtendedMasterSecretExtensionHandler(context);
    }

}
