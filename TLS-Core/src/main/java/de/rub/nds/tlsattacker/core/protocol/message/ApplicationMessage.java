/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement(name = "Application")
public class ApplicationMessage extends TlsMessage<ApplicationMessage> {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] dataConfig = null;

    @ModifiableVariableProperty
    private ModifiableByteArray data;

    public ApplicationMessage(Config tlsConfig, byte[] dataConfig) {
        super();
        this.dataConfig = dataConfig;
        this.protocolMessageType = TlsMessageType.APPLICATION_DATA;
    }

    public ApplicationMessage() {
        super();
        this.protocolMessageType = TlsMessageType.APPLICATION_DATA;
    }

    public ApplicationMessage(Config tlsConfig) {
        super();
        this.protocolMessageType = TlsMessageType.APPLICATION_DATA;
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
    public ApplicationMessageHandler getHandler(TlsContext context) {
        return new ApplicationMessageHandler(context);
    }

    @Override
    public ApplicationMessageParser getParser(TlsContext context, InputStream stream) {
        return new ApplicationMessageParser(stream, context.getChooser().getLastRecordVersion(), context.getConfig());
    }

    @Override
    public ApplicationMessagePreparator getPreparator(TlsContext context) {
        return new ApplicationMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ApplicationMessageSerializer getSerializer(TlsContext context) {
        return new ApplicationMessageSerializer(this, context.getChooser().getSelectedProtocolVersion());
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
