/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.quic.QuicTransportParametersExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.quic.QuicTransportParametersExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.quic.QuicTransportParametersExtensionsPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.quic.QuicTransportParametersExtensionsSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.bouncycastle.util.Arrays;

@XmlRootElement(name = "QuicTransportParametersExtension")
public class QuicTransportParametersExtensionMessage
        extends ExtensionMessage<QuicTransportParametersExtensionMessage> {

    @ModifiableVariableProperty private ModifiableInteger parameterExtensionsLength;
    @ModifiableVariableProperty private ModifiableByteArray parameterExtensions;
    @HoldsModifiableVariable private List<QuicTransportParameterEntry> transportParameterEntries;

    private QuicTransportParameters quicTransportParameters;

    public QuicTransportParametersExtensionMessage() {
        super(ExtensionType.QUIC_TRANSPORT_PARAMETERS);
        transportParameterEntries = new ArrayList<>();
    }

    public QuicTransportParametersExtensionMessage(Config config) {
        super(ExtensionType.QUIC_TRANSPORT_PARAMETERS);
        transportParameterEntries = new ArrayList<>();
    }

    public ModifiableInteger getParameterExtensionsLength() {
        return parameterExtensionsLength;
    }

    public void setParameterExtensionsLength(ModifiableInteger parameterExtensionsLength) {
        this.parameterExtensionsLength = parameterExtensionsLength;
    }

    public void setParameterExtensionsLength(int parameterExtensionsLength) {
        this.parameterExtensionsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.parameterExtensionsLength, parameterExtensionsLength);
    }

    public ModifiableByteArray getParameterExtensions() {
        return parameterExtensions;
    }

    public void setParameterExtensions(ModifiableByteArray parameterExtensions) {
        this.parameterExtensions = parameterExtensions;
    }

    public void setParameterExtensions(byte[] parameterExtensions) {
        this.parameterExtensions =
                ModifiableVariableFactory.safelySetValue(
                        this.parameterExtensions, parameterExtensions);
    }

    public List<QuicTransportParameterEntry> getTransportParameterEntries() {
        return transportParameterEntries;
    }

    public void setTransportParameterEntries(
            List<QuicTransportParameterEntry> transportParameterEntries) {
        this.transportParameterEntries = transportParameterEntries;
    }

    public QuicTransportParameters getQuicTransportParameters() {
        return quicTransportParameters;
    }

    public void setQuicTransportParameters(QuicTransportParameters quicTransportParameters) {
        this.quicTransportParameters = quicTransportParameters;
    }

    @Override
    public ExtensionHandler<QuicTransportParametersExtensionMessage> getHandler(
            TlsContext context) {
        return new QuicTransportParametersExtensionsHandler(context);
    }

    @Override
    public ExtensionSerializer<QuicTransportParametersExtensionMessage> getSerializer(
            TlsContext context) {
        return new QuicTransportParametersExtensionsSerializer(this);
    }

    @Override
    public ExtensionPreparator<QuicTransportParametersExtensionMessage> getPreparator(
            TlsContext context) {
        return new QuicTransportParametersExtensionsPreparator(
                context.getChooser(), this, getSerializer(context));
    }

    @Override
    public ExtensionParser<QuicTransportParametersExtensionMessage> getParser(
            TlsContext context, InputStream stream) {
        return new QuicTransportParametersExtensionParser(stream, context);
    }

    @Override
    public String toString() {
        return "QuicTransportParametersExtensionMessage{\n"
                + this.transportParameterEntries.stream()
                        .map(QuicTransportParameterEntry::toString)
                        .collect(Collectors.joining(",\n"))
                + "\n}";
    }

    /**
     * Preferred Address { IPv4 Address (32), IPv4 Port (16), IPv6 Address (128), IPv6 Port (16),
     * Connection ID Length (8), Connection ID (..), Stateless Reset Token (128), }
     */
    public static class PreferredAddress {
        private InetAddress ipv4Address;
        private int ipv4Port;
        private InetAddress ipv6Address;
        private int ipv6Port;
        private int connectionIdLength;
        private byte[] connectionId;
        private byte[] statelessResetToken;

        public PreferredAddress(byte[] entryValue) {
            try {
                this.ipv4Address = InetAddress.getByAddress(Arrays.copyOfRange(entryValue, 0, 4));
            } catch (UnknownHostException e) {
                this.ipv4Address = null;
            }
            this.ipv4Port = ArrayConverter.bytesToInt(Arrays.copyOfRange(entryValue, 4, 6));
            try {
                this.ipv6Address = InetAddress.getByAddress(Arrays.copyOfRange(entryValue, 6, 22));
            } catch (UnknownHostException e) {
                this.ipv6Address = null;
            }
            this.ipv6Port = ArrayConverter.bytesToInt(Arrays.copyOfRange(entryValue, 22, 24));
            this.connectionIdLength =
                    ArrayConverter.bytesToInt(Arrays.copyOfRange(entryValue, 24, 25));
            this.connectionId = Arrays.copyOfRange(entryValue, 25, 25 + this.connectionIdLength);
            this.statelessResetToken =
                    Arrays.copyOfRange(
                            entryValue,
                            25 + this.connectionIdLength,
                            25 + this.connectionIdLength + 16);
        }

        @Override
        public String toString() {
            return "PreferredAddress{"
                    + "ipv4Address="
                    + ipv4Address
                    + ", ipv4Port="
                    + ipv4Port
                    + ", ipv6Address="
                    + ipv6Address
                    + ", ipv6Port="
                    + ipv6Port
                    + ", connectionId="
                    + ArrayConverter.bytesToHexString(connectionId)
                    + ", statelessResetToken="
                    + ArrayConverter.bytesToHexString(statelessResetToken)
                    + '}';
        }

        public byte[] serialize() throws IOException {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(this.ipv4Address.getAddress());
            byteArrayOutputStream.write(this.ipv4Port);
            byteArrayOutputStream.write(this.ipv6Address.getAddress());
            byteArrayOutputStream.write(this.ipv6Port);
            byteArrayOutputStream.write(this.connectionId.length);
            byteArrayOutputStream.write(this.connectionId);
            byteArrayOutputStream.write(this.statelessResetToken);
            return byteArrayOutputStream.toByteArray();
        }

        public InetAddress getIpv4Address() {
            return ipv4Address;
        }

        public void setIpv4Address(InetAddress ipv4Address) {
            this.ipv4Address = ipv4Address;
        }

        public int getIpv4Port() {
            return ipv4Port;
        }

        public void setIpv4Port(int ipv4Port) {
            this.ipv4Port = ipv4Port;
        }

        public InetAddress getIpv6Address() {
            return ipv6Address;
        }

        public void setIpv6Address(InetAddress ipv6Address) {
            this.ipv6Address = ipv6Address;
        }

        public int getIpv6Port() {
            return ipv6Port;
        }

        public void setIpv6Port(int ipv6Port) {
            this.ipv6Port = ipv6Port;
        }

        public int getConnectionIdLength() {
            return connectionIdLength;
        }

        public void setConnectionIdLength(int connectionIdLength) {
            this.connectionIdLength = connectionIdLength;
        }

        public byte[] getConnectionId() {
            return connectionId;
        }

        public void setConnectionId(byte[] connectionId) {
            this.connectionId = connectionId;
        }

        public byte[] getStatelessResetToken() {
            return statelessResetToken;
        }

        public void setStatelessResetToken(byte[] statelessResetToken) {
            this.statelessResetToken = statelessResetToken;
        }
    }
}
