/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.InputStream;
import java.util.Arrays;

@XmlRootElement(name = "Application")
public class ApplicationMessage extends ProtocolMessage<ApplicationMessage> {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dataConfig = null;

    @ModifiableVariableProperty private ModifiableByteArray data;

    public ApplicationMessage(byte[] dataConfig) {
        super();
        this.dataConfig = dataConfig;
        this.protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
    }

    public ApplicationMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.APPLICATION_DATA;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        if (this.data == null) {
            this.data = new ModifiableByteArray();
        }
        this.data.setOriginalValue(data);
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ApplicationMessage:");
        sb.append("\n  Data: ");
        if (data != null && data.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(data.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "APPLICATION";
    }

    @Override
    public String toShortString() {
        return "APP";
    }

    @Override
    public ApplicationMessageHandler getHandler(TlsContext tlsContext) {
        return new ApplicationMessageHandler(tlsContext);
    }

    @Override
    public ApplicationMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ApplicationMessageParser(stream);
    }

    @Override
    public ApplicationMessagePreparator getPreparator(TlsContext tlsContext) {
        return new ApplicationMessagePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ApplicationMessageSerializer getSerializer(TlsContext tlsContext) {
        return new ApplicationMessageSerializer(this);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + Arrays.hashCode(this.dataConfig);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ApplicationMessage other = (ApplicationMessage) obj;
        return Arrays.equals(this.dataConfig, other.dataConfig);
    }
}
