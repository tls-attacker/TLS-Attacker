/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownHandshakeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

@XmlRootElement(name = "UnknownHandshakeMessage")
public class UnknownHandshakeMessage extends HandshakeMessage<UnknownHandshakeMessage> {

    private byte[] dataConfig;

    @ModifiableVariableProperty private ModifiableByteArray data;

    public UnknownHandshakeMessage() {
        super(HandshakeMessageType.UNKNOWN);
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public UnknownHandshakeHandler getHandler(TlsContext tlsContext) {
        return new UnknownHandshakeHandler(tlsContext);
    }

    @Override
    public UnknownHandshakeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new UnknownHandshakeParser(stream, tlsContext);
    }

    @Override
    public UnknownHandshakePreparator getPreparator(TlsContext tlsContext) {
        return new UnknownHandshakePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public UnknownHandshakeSerializer getSerializer(TlsContext tlsContext) {
        return new UnknownHandshakeSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnknownHandshakeMessage:");
        sb.append("\n  Data: ");
        if (data != null && data.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(data.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "HS(?)";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 17 * hash + Arrays.hashCode(this.dataConfig);
        hash = 17 * hash + Objects.hashCode(this.data);
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
        final UnknownHandshakeMessage other = (UnknownHandshakeMessage) obj;
        if (!Arrays.equals(this.dataConfig, other.dataConfig)) {
            return false;
        }
        return Objects.equals(this.data, other.data);
    }
}
