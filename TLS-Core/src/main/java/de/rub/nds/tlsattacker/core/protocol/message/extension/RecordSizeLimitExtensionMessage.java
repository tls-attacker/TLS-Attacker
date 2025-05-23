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
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.RecordSizeLimitExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.RecordSizeLimitExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RecordSizeLimitExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** Record Size Limit Extension described in RFC 8449 */
@XmlRootElement(name = "RecordSizeLimitExtension")
public class RecordSizeLimitExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableByteArray recordSizeLimit;

    public RecordSizeLimitExtensionMessage(Config config) {
        super(ExtensionType.RECORD_SIZE_LIMIT);
    }

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
        this.recordSizeLimit =
                ModifiableVariableFactory.safelySetValue(this.recordSizeLimit, recordSizeLimit);
    }

    @Override
    public RecordSizeLimitExtensionParser getParser(Context context, InputStream stream) {
        return new RecordSizeLimitExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public RecordSizeLimitExtensionPreparator getPreparator(Context context) {
        return new RecordSizeLimitExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public RecordSizeLimitExtensionSerializer getSerializer(Context context) {
        return new RecordSizeLimitExtensionSerializer(this);
    }

    @Override
    public RecordSizeLimitExtensionHandler getHandler(Context context) {
        return new RecordSizeLimitExtensionHandler(context.getTlsContext());
    }
}
