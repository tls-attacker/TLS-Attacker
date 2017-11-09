/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import java.util.List;

public class TrustedCaIndicationExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableInteger trustedAuthoritiesLength;
    @HoldsModifiableVariable
    private List<TrustedAuthority> trustedAuthorities;
    @ModifiableVariableProperty
    private ModifiableByteArray trustedAuthoritiesBytes;

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
        this.trustedAuthoritiesLength = ModifiableVariableFactory.safelySetValue(this.trustedAuthoritiesLength,
                trustedAuthoritiesLength);
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
        this.trustedAuthoritiesBytes = ModifiableVariableFactory.safelySetValue(this.trustedAuthoritiesBytes,
                trustedAuthoritiesBytes);
    }

}
