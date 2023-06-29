/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TrustedCaIndicationExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedCaIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TrustedCaIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

@XmlRootElement(name = "TrustedCaIndicationExtension")
public class TrustedCaIndicationExtensionMessage
        extends ExtensionMessage<TrustedCaIndicationExtensionMessage> {

    @ModifiableVariableProperty private ModifiableInteger trustedAuthoritiesLength;
    @HoldsModifiableVariable private List<TrustedAuthority> trustedAuthorities;
    @ModifiableVariableProperty private ModifiableByteArray trustedAuthoritiesBytes;

    public TrustedCaIndicationExtensionMessage() {
        super(ExtensionType.TRUSTED_CA_KEYS);
    }

    public ModifiableInteger getTrustedAuthoritiesLength() {
        return trustedAuthoritiesLength;
    }

    public void setTrustedAuthoritiesLength(ModifiableInteger trustedAuthoritiesLength) {
        this.trustedAuthoritiesLength = trustedAuthoritiesLength;
    }

    public void setTrustedAuthoritiesLength(int trustedAuthoritiesLength) {
        this.trustedAuthoritiesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.trustedAuthoritiesLength, trustedAuthoritiesLength);
    }

    public List<TrustedAuthority> getTrustedAuthorities() {
        return trustedAuthorities;
    }

    public void setTrustedAuthorities(List<TrustedAuthority> trustedAuthorities) {
        this.trustedAuthorities = trustedAuthorities;
    }

    public ModifiableByteArray getTrustedAuthoritiesBytes() {
        return trustedAuthoritiesBytes;
    }

    public void setTrustedAuthoritiesBytes(ModifiableByteArray trustedAuthoritiesBytes) {
        this.trustedAuthoritiesBytes = trustedAuthoritiesBytes;
    }

    public void setTrustedAuthoritiesBytes(byte[] trustedAuthoritiesBytes) {
        this.trustedAuthoritiesBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.trustedAuthoritiesBytes, trustedAuthoritiesBytes);
    }

    @Override
    public TrustedCaIndicationExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new TrustedCaIndicationExtensionParser(stream, tlsContext);
    }

    @Override
    public TrustedCaIndicationExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new TrustedCaIndicationExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public TrustedCaIndicationExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new TrustedCaIndicationExtensionSerializer(this);
    }

    @Override
    public TrustedCaIndicationExtensionHandler getHandler(TlsContext tlsContext) {
        return new TrustedCaIndicationExtensionHandler(tlsContext);
    }
}
