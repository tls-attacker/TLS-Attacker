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
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UnknownExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UnknownExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;

@XmlRootElement(name = "UnknownExtension")
public class UnknownExtensionMessage extends ExtensionMessage {

    private byte[] typeConfig;
    private Integer lengthConfig;
    private byte[] dataConfig;

    @ModifiableVariableProperty private ModifiableByteArray extensionData;

    public UnknownExtensionMessage() {
        super(ExtensionType.UNKNOWN);
    }

    public Integer getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public byte[] getTypeConfig() {
        return typeConfig;
    }

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    public void setTypeConfig(byte[] typeConfig) {
        this.typeConfig = typeConfig;
    }

    public ModifiableByteArray getExtensionData() {
        return extensionData;
    }

    public void setExtensionData(ModifiableByteArray extensionData) {
        this.extensionData = extensionData;
    }

    public void setExtensionData(byte[] extensionData) {
        this.extensionData =
                ModifiableVariableFactory.safelySetValue(this.extensionData, extensionData);
    }

    @Override
    public String toString() {
        return "UnknownExtensionMessage";
    }

    @Override
    public UnknownExtensionParser getParser(Context context, InputStream stream) {
        return new UnknownExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public UnknownExtensionPreparator getPreparator(Context context) {
        return new UnknownExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public UnknownExtensionSerializer getSerializer(Context context) {
        return new UnknownExtensionSerializer(this);
    }

    @Override
    public UnknownExtensionHandler getHandler(Context context) {
        return new UnknownExtensionHandler(context.getTlsContext());
    }
}
