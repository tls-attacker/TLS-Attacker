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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SrtpExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SrtpExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SrtpExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SrtpExtensionSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC5764 */
@XmlRootElement(name = "SrtpExtension")
public class SrtpExtensionMessage extends ExtensionMessage<SrtpExtensionMessage> {

    @ModifiableVariableProperty private ModifiableByteArray srtpProtectionProfiles;
    @ModifiableVariableProperty private ModifiableInteger srtpProtectionProfilesLength; // 2 Byte
    @ModifiableVariableProperty private ModifiableByteArray srtpMki; // SRTP Master Key Identifier
    @ModifiableVariableProperty private ModifiableInteger srtpMkiLength; // 1 Byte

    public SrtpExtensionMessage() {
        super(ExtensionType.USE_SRTP);
    }

    public ModifiableByteArray getSrtpProtectionProfiles() {
        return srtpProtectionProfiles;
    }

    public void setSrtpProtectionProfiles(ModifiableByteArray srtpProtectionProfiles) {
        this.srtpProtectionProfiles = srtpProtectionProfiles;
    }

    public void setSrtpProtectionProfiles(byte[] srtpProtectionProfiles) {
        this.srtpProtectionProfiles =
                ModifiableVariableFactory.safelySetValue(
                        this.srtpProtectionProfiles, srtpProtectionProfiles);
    }

    public ModifiableInteger getSrtpProtectionProfilesLength() {
        return srtpProtectionProfilesLength;
    }

    public void setSrtpProtectionProfilesLength(ModifiableInteger srtpProtectionProfilesLength) {
        this.srtpProtectionProfilesLength = srtpProtectionProfilesLength;
    }

    public void setSrtpProtectionProfilesLength(int srtpProtectionProfilesLength) {
        this.srtpProtectionProfilesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.srtpProtectionProfilesLength, srtpProtectionProfilesLength);
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
        this.srtpMkiLength =
                ModifiableVariableFactory.safelySetValue(this.srtpMkiLength, srtpMkiLength);
    }

    @Override
    public SrtpExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SrtpExtensionParser(stream, tlsContext);
    }

    @Override
    public SrtpExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SrtpExtensionPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public SrtpExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SrtpExtensionSerializer(this);
    }

    @Override
    public SrtpExtensionHandler getHandler(TlsContext tlsContext) {
        return new SrtpExtensionHandler(tlsContext);
    }
}
