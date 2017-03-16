/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class UnknownExtensionMessage extends ExtensionMessage {

    private byte[] typeConfig;
    private int lengthConfig;
    private byte[] dataConfig;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionData;

    public UnknownExtensionMessage(TlsConfig tlsConfig) {
        super();
        this.extensionTypeConstant = ExtensionType.UNKNOWN;
    }

    public UnknownExtensionMessage() {
        super();
        this.extensionTypeConstant = ExtensionType.UNKNOWN;
    }

    public int getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public byte[] getTypeConfig() {
        return typeConfig;
    }

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
        this.extensionData = ModifiableVariableFactory.safelySetValue(this.extensionData, extensionData);
    }

    @Override
    public String toString() {
        return "UnknownExtensionMessage{ extensionData="
                + ArrayConverter.bytesToHexString(extensionType.getValue(), false) + " extensionLength="
                + extensionLength.getValue() + " extensionData="
                + ArrayConverter.bytesToHexString(extensionData.getValue(), false) + '}';
    }

    @Override
    public ExtensionPreparator<? extends ExtensionMessage> getExtensionPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    public ExtensionSerializer<? extends ExtensionMessage> getExtensionSerializer() {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

}
