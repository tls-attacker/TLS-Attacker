/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SrtpExtensionHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SrtpExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    ModifiableByteArray srtpProtectionProfiles;
    @ModifiableVariableProperty
    ModifiableInteger srtpProtectionProfilesLength; // 2 Byte
    @ModifiableVariableProperty
    ModifiableByteArray srtpMki; // SRTP Master Key Identifier
    @ModifiableVariableProperty
    ModifiableInteger srtpMkiLength; // 1 Byte

    public SrtpExtensionMessage() {
        super(ExtensionType.USE_SRTP);
    }

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new SrtpExtensionHandler(context);
    }

    public ModifiableByteArray getSrtpProtectionProfiles() {
        return srtpProtectionProfiles;
    }

    public void setSrtpProtectionProfiles(ModifiableByteArray srtpProtectionProfiles) {
        this.srtpProtectionProfiles = srtpProtectionProfiles;
    }

    public void setSrtpProtectionProfiles(byte[] srtpProtectionProfiles) {
        this.srtpProtectionProfiles = ModifiableVariableFactory.safelySetValue(this.srtpProtectionProfiles,
                srtpProtectionProfiles);
    }

    public ModifiableInteger getSrtpProtectionProfilesLength() {
        return srtpProtectionProfilesLength;
    }

    public void setSrtpProtectionProfilesLength(ModifiableInteger srtpProtectionProfilesLength) {
        this.srtpProtectionProfilesLength = srtpProtectionProfilesLength;
    }

    public void setSrtpProtectionProfilesLength(int srtpProtectionProfilesLength) {
        this.srtpProtectionProfilesLength = ModifiableVariableFactory.safelySetValue(this.srtpProtectionProfilesLength,
                srtpProtectionProfilesLength);
    }

    public ModifiableByteArray getSrtpMki() {
        return srtpMki;
    }

    public void setSrtpMki(ModifiableByteArray srtpMki) {
        this.srtpMki = srtpMki;
    }

    public void setSrtpMki(byte[] srtpMki) {
        this.srtpMki = ModifiableVariableFactory.safelySetValue(this.srtpMki, srtpMki);
    }

    public ModifiableInteger getSrtpMkiLength() {
        return srtpMkiLength;
    }

    public void setSrtpMkiLength(ModifiableInteger srtpMkiLength) {
        this.srtpMkiLength = srtpMkiLength;
    }

    public void setSrtpMkiLength(int srtpMkiLength) {
        this.srtpMkiLength = ModifiableVariableFactory.safelySetValue(this.srtpMkiLength, srtpMkiLength);
    }

}
