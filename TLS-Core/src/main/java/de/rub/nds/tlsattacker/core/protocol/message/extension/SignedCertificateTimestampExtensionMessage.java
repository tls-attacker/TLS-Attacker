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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC6962 */
@XmlRootElement(name = "SignedCertificateTimestampExtension")
public class SignedCertificateTimestampExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableByteArray singedTimestamp;

    /** Constructor */
    public SignedCertificateTimestampExtensionMessage() {
        super(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
    }

    /**
     * @return the raw signedTimestamp
     */
    public ModifiableByteArray getSignedTimestamp() {
        return singedTimestamp;
    }

    /**
     * @param singedTimestamp - Timestamp as ModifiableByteArray
     */
    public void setSignedTimestamp(ModifiableByteArray singedTimestamp) {
        this.singedTimestamp = singedTimestamp;
    }

    /**
     * @param singedTimestamp - Timestamp as byte array
     */
    public void setSignedTimestamp(byte[] singedTimestamp) {
        this.singedTimestamp =
                ModifiableVariableFactory.safelySetValue(this.singedTimestamp, singedTimestamp);
    }

    @Override
    public SignedCertificateTimestampExtensionParser getParser(
            Context context, InputStream stream) {
        return new SignedCertificateTimestampExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public SignedCertificateTimestampExtensionPreparator getPreparator(Context context) {
        return new SignedCertificateTimestampExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public SignedCertificateTimestampExtensionSerializer getSerializer(Context context) {
        return new SignedCertificateTimestampExtensionSerializer(this);
    }

    @Override
    public SignedCertificateTimestampExtensionHandler getHandler(Context context) {
        return new SignedCertificateTimestampExtensionHandler(context.getTlsContext());
    }
}
