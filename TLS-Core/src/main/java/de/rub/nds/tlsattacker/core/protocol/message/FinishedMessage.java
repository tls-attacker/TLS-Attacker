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
import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "Finished")
public class FinishedMessage extends HandshakeMessage<FinishedMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray verifyData;

    public FinishedMessage() {
        super(HandshakeMessageType.FINISHED);
    }

    public ModifiableByteArray getVerifyData() {
        return verifyData;
    }

    public void setVerifyData(ModifiableByteArray verifyData) {
        this.verifyData = verifyData;
    }

    public void setVerifyData(byte[] value) {
        this.verifyData = ModifiableVariableFactory.safelySetValue(this.verifyData, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("FinishedMessage:");
        sb.append("\n  Verify Data: ");
        if (verifyData != null && verifyData.getOriginalValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(verifyData.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "FIN";
    }

    @Override
    public FinishedHandler getHandler(TlsContext tlsContext) {
        return new FinishedHandler(tlsContext);
    }

    @Override
    public FinishedParser getParser(TlsContext tlsContext, InputStream stream) {
        return new FinishedParser(stream, tlsContext);
    }

    @Override
    public FinishedPreparator getPreparator(TlsContext tlsContext) {
        return new FinishedPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public FinishedSerializer getSerializer(TlsContext tlsContext) {
        return new FinishedSerializer(this);
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.verifyData);
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
        final FinishedMessage other = (FinishedMessage) obj;
        return Objects.equals(this.verifyData, other.verifyData);
    }
}
