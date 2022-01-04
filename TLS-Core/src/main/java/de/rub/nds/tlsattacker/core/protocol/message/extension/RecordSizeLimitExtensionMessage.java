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
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RecordSizeLimitExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RecordSizeLimitExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RecordSizeLimitExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * Record Size Limit Extension described in RFC 8449
 */
@XmlRootElement(name = "RecordSizeLimitExtension")
public class RecordSizeLimitExtensionMessage extends ExtensionMessage<RecordSizeLimitExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableByteArray recordSizeLimit;

    public RecordSizeLimitExtensionMessage() {
        super(ExtensionType.RECORD_SIZE_LIMIT);
    }

    public ModifiableByteArray getRecordSizeLimit() {
        return this.recordSizeLimit;
    }

    public void setRecordSizeLimit(ModifiableByteArray recordSizeLimit) {
        this.recordSizeLimit = recordSizeLimit;
    }

    public void setRecordSizeLimit(byte[] recordSizeLimit) {
        this.recordSizeLimit = ModifiableVariableFactory.safelySetValue(this.recordSizeLimit, recordSizeLimit);
    }

    @Override
    public RecordSizeLimitExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new RecordSizeLimitExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public RecordSizeLimitExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new RecordSizeLimitExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public RecordSizeLimitExtensionSerializer getSerializer(TlsContext tlsContetx) {
        return new RecordSizeLimitExtensionSerializer(this);
    }

    @Override
    public RecordSizeLimitExtensionHandler getHandler(TlsContext tlsContext) {
        return new RecordSizeLimitExtensionHandler(tlsContext);
    }

}
