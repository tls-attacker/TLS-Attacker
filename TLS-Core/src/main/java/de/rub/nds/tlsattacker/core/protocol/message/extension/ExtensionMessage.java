/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlSeeAlso;

@XmlSeeAlso({EncryptedServerNameIndicationExtensionMessage.class, ECPointFormatExtensionMessage.class,
    EllipticCurvesExtensionMessage.class, EllipticCurvesExtensionMessage.class,
    ExtendedMasterSecretExtensionMessage.class, GreaseExtensionMessage.class, HeartbeatExtensionMessage.class,
    MaxFragmentLengthExtensionMessage.class, RecordSizeLimitExtensionMessage.class, PaddingExtensionMessage.class,
    RenegotiationInfoExtensionMessage.class, ServerNameIndicationExtensionMessage.class,
    SessionTicketTLSExtensionMessage.class, SignatureAndHashAlgorithmsExtensionMessage.class,
    SignedCertificateTimestampExtensionMessage.class, ExtendedRandomExtensionMessage.class,
    TokenBindingExtensionMessage.class, KeyShareExtensionMessage.class, SupportedVersionsExtensionMessage.class,
    AlpnExtensionMessage.class, CertificateStatusRequestExtensionMessage.class,
    CertificateStatusRequestV2ExtensionMessage.class, CertificateTypeExtensionMessage.class,
    ClientCertificateUrlExtensionMessage.class, ClientCertificateTypeExtensionMessage.class,
    ClientAuthzExtensionMessage.class, EncryptThenMacExtensionMessage.class, ServerAuthzExtensionMessage.class,
    ServerCertificateTypeExtensionMessage.class, SrtpExtensionMessage.class, TrustedCaIndicationExtensionMessage.class,
    TruncatedHmacExtensionMessage.class, EarlyDataExtensionMessage.class, PSKKeyExchangeModesExtensionMessage.class,
    PreSharedKeyExtensionMessage.class, UnknownExtensionMessage.class, PWDClearExtensionMessage.class,
    PWDProtectExtensionMessage.class, PasswordSaltExtensionMessage.class, CachedInfoExtensionMessage.class,
    CookieExtensionMessage.class, DtlsHandshakeMessageFragment.class, UserMappingExtensionMessage.class,
    SRPExtensionMessage.class, CachedInfoExtensionMessage.class})
public abstract class ExtensionMessage<Self extends ExtensionMessage> extends ModifiableVariableHolder
        implements Serializable, DataContainer<Self> {

    protected ExtensionType extensionTypeConstant;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray extensionType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionLength;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty
    private ModifiableByteArray payloadBytes;

    public ExtensionMessage() {
    }

    public ExtensionMessage(ExtensionType type) {
        this.extensionTypeConstant = type;
    }

    public ModifiableByteArray getExtensionType() {
        return extensionType;
    }

    public ModifiableInteger getExtensionLength() {
        return extensionLength;
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionType(byte[] array) {
        this.extensionType = ModifiableVariableFactory.safelySetValue(extensionType, array);
    }

    public void setExtensionType(ModifiableByteArray extensionType) {
        this.extensionType = extensionType;
    }

    public void setExtensionLength(int length) {
        this.extensionLength = ModifiableVariableFactory.safelySetValue(extensionLength, length);
    }

    public void setExtensionLength(ModifiableInteger extensionLength) {
        this.extensionLength = extensionLength;
    }

    public void setExtensionBytes(byte[] data) {
        this.extensionBytes = ModifiableVariableFactory.safelySetValue(extensionBytes, data);
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public ModifiableByteArray getPayloadBytes() {
        return payloadBytes;
    }

    public void setPayloadBytes(ModifiableByteArray payloadBytes) {
        this.payloadBytes = payloadBytes;
    }

    public void setPayloadBytes(byte[] payloadBytes) {
        this.payloadBytes = ModifiableVariableFactory.safelySetValue(this.payloadBytes, payloadBytes);
    }

    public ExtensionType getExtensionTypeConstant() {
        return extensionTypeConstant;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (extensionType == null || extensionType.getValue() == null) {
            sb.append("\n    Extension type: null");
        } else {
            sb.append("\n    Extension type: ").append(ArrayConverter.bytesToHexString(extensionType.getValue()));
        }
        if (extensionLength == null || extensionLength.getValue() == null) {
            sb.append("\n    Extension length: null");

        } else {
            sb.append("\n    Extension length: ").append(extensionLength.getValue());
        }
        return sb.toString();
    }

    @Override
    public abstract ExtensionHandler<Self> getHandler(TlsContext context);

    @Override
    public abstract ExtensionSerializer<Self> getSerializer(TlsContext context);

    @Override
    public abstract ExtensionPreparator<Self> getPreparator(TlsContext context);

    @Override
    public abstract ExtensionParser<Self> getParser(TlsContext context, InputStream stream);

}
