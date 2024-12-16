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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.CertificateStatusRequestV2ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestV2ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestV2ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;

/** RFC 6961 */
@XmlRootElement(name = "CertificateStatusRequestV2Extension")
public class CertificateStatusRequestV2ExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty private ModifiableInteger statusRequestListLength;
    @HoldsModifiableVariable private List<RequestItemV2> statusRequestList;
    @ModifiableVariableProperty private ModifiableByteArray statusRequestBytes;

    public CertificateStatusRequestV2ExtensionMessage() {
        super(ExtensionType.STATUS_REQUEST_V2);
    }

    public ModifiableInteger getStatusRequestListLength() {
        return statusRequestListLength;
    }

    public void setStatusRequestListLength(ModifiableInteger statusRequestListLength) {
        this.statusRequestListLength = statusRequestListLength;
    }

    public void setStatusRequestListLength(int statusRequestListLength) {
        this.statusRequestListLength =
                ModifiableVariableFactory.safelySetValue(
                        this.statusRequestListLength, statusRequestListLength);
    }

    public List<RequestItemV2> getStatusRequestList() {
        return statusRequestList;
    }

    public void setStatusRequestList(List<RequestItemV2> statusRequestList) {
        this.statusRequestList = statusRequestList;
    }

    public ModifiableByteArray getStatusRequestBytes() {
        return statusRequestBytes;
    }

    public void setStatusRequestBytes(ModifiableByteArray statusRequestBytes) {
        this.statusRequestBytes = statusRequestBytes;
    }

    public void setStatusRequestBytes(byte[] statusRequestBytes) {
        this.statusRequestBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.statusRequestBytes, statusRequestBytes);
    }

    @Override
    public CertificateStatusRequestV2ExtensionParser getParser(
            Context context, InputStream stream) {
        return new CertificateStatusRequestV2ExtensionParser(stream, context.getTlsContext());
    }

    @Override
    public CertificateStatusRequestV2ExtensionPreparator getPreparator(Context context) {
        return new CertificateStatusRequestV2ExtensionPreparator(context.getChooser(), this);
    }

    @Override
    public CertificateStatusRequestV2ExtensionSerializer getSerializer(Context context) {
        return new CertificateStatusRequestV2ExtensionSerializer(this);
    }

    @Override
    public CertificateStatusRequestV2ExtensionHandler getHandler(Context context) {
        return new CertificateStatusRequestV2ExtensionHandler(context.getTlsContext());
    }
}
