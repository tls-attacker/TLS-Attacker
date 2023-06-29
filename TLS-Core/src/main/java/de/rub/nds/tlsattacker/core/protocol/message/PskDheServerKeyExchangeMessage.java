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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.DHEServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.PskDheServerKeyExchangeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDheServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskDheServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskDheServerKeyExchangeSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "PskDheServerKeyExchange")
public class PskDheServerKeyExchangeMessage
        extends DHEServerKeyExchangeMessage<PskDheServerKeyExchangeMessage> {

    private ModifiableByteArray identityHint;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger identityHintLength;

    public PskDheServerKeyExchangeMessage() {
        super();
    }

    public ModifiableByteArray getIdentityHint() {
        return identityHint;
    }

    public void setIdentityHint(ModifiableByteArray identityHint) {
        this.identityHint = identityHint;
    }

    public void setIdentityHint(byte[] identity) {
        this.identityHint = ModifiableVariableFactory.safelySetValue(this.identityHint, identity);
    }

    public ModifiableInteger getIdentityHintLength() {
        return identityHintLength;
    }

    public void setIdentityHintLength(ModifiableInteger identityHintLength) {
        this.identityHintLength = identityHintLength;
    }

    public void setIdentityHintLength(int identityHintLength) {
        this.identityHintLength =
                ModifiableVariableFactory.safelySetValue(
                        this.identityHintLength, identityHintLength);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PskDheServerKeyExchangeMessage:");
        sb.append("\n  Modulus p: ");
        if (super.modulus != null && super.modulus.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(modulus.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Generator g: ");
        if (generator != null && generator.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(generator.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Public Key: ");
        if (getPublicKey() != null) {
            sb.append(ArrayConverter.bytesToHexString(getPublicKey().getValue(), false));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public DHEServerKeyExchangeHandler<PskDheServerKeyExchangeMessage> getHandler(
            TlsContext tlsContext) {
        return new PskDheServerKeyExchangeHandler(tlsContext);
    }

    @Override
    public PskDheServerKeyExchangeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new PskDheServerKeyExchangeParser(stream, tlsContext);
    }

    @Override
    public PskDheServerKeyExchangePreparator getPreparator(TlsContext tlsContext) {
        return new PskDheServerKeyExchangePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public PskDheServerKeyExchangeSerializer getSerializer(TlsContext tlsContext) {
        return new PskDheServerKeyExchangeSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append("DHE_PSK_SERVER_KEY_EXCHANGE");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "PSK_DHE_CKE";
    }
}
