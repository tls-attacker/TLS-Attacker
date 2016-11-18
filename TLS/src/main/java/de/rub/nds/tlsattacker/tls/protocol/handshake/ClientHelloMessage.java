/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
// @XmlType(propOrder = {"compressionLength", "cipherSuiteLength"})
public class ClientHelloMessage extends HelloMessage {

    /**
     * List of supported compression methods
     */
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = CompressionMethod.class, name = "CompressionMethod") })
    private List<CompressionMethod> supportedCompressionMethods = new LinkedList<>();
    /**
     * List of supported ciphersuites
     */
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = CipherSuite.class, name = "CipherSuite") })
    private List<CipherSuite> supportedCipherSuites = new LinkedList<>();
    /**
     * compression length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger compressionLength;
    /**
     * cipher suite byte length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger cipherSuiteLength;
    /**
     * array of supported ciphersuites
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray cipherSuites;
    /**
     * array of supported compressions
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByteArray compressions;
    /**
     * array of all extension bytes to forward them as MitM
     */
    byte[] extensionBytes;

    public ClientHelloMessage() {
        super(HandshakeMessageType.CLIENT_HELLO);
    }

    public ModifiableInteger getCompressionLength() {
        return compressionLength;
    }

    public ModifiableInteger getCipherSuiteLength() {
        return cipherSuiteLength;
    }

    public ModifiableByteArray getCipherSuites() {
        return cipherSuites;
    }

    public ModifiableByteArray getCompressions() {
        return compressions;
    }

    public void setCompressionLength(ModifiableInteger compressionLength) {
        this.compressionLength = compressionLength;
    }

    public void setCipherSuiteLength(ModifiableInteger cipherSuiteLength) {
        this.cipherSuiteLength = cipherSuiteLength;
    }

    public void setCipherSuites(ModifiableByteArray cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public void setCompressions(ModifiableByteArray compressions) {
        this.compressions = compressions;
    }

    public void setCompressionLength(int compressionLength) {
        this.compressionLength = ModifiableVariableFactory.safelySetValue(this.compressionLength, compressionLength);
    }

    public void setCipherSuiteLength(int cipherSuiteLength) {
        this.cipherSuiteLength = ModifiableVariableFactory.safelySetValue(this.cipherSuiteLength, cipherSuiteLength);
    }

    public void setCipherSuites(byte[] array) {
        this.cipherSuites = ModifiableVariableFactory.safelySetValue(cipherSuites, array);
    }

    public void setCompressions(byte[] array) {
        this.compressions = ModifiableVariableFactory.safelySetValue(compressions, array);
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public void setSupportedCipherSuites(List<CipherSuite> supportedCipherSuites) {
        this.supportedCipherSuites = supportedCipherSuites;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public byte[] getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes = extensionBytes;
    }

    public List<CipherSuite> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("\n  Protocol Version: ")
                .append(ProtocolVersion.getProtocolVersion(protocolVersion.getValue()))
                .append("\n  Client Unix Time: ")
                .append(new Date(ArrayConverter.bytesToLong(unixTime.getValue()) * 1000)).append("\n  Client Random: ")
                .append(ArrayConverter.bytesToHexString(random.getValue())).append("\n  Session ID: ")
                .append(ArrayConverter.bytesToHexString(sessionId.getValue())).append("\n  Supported Cipher Suites: ")
                .append(ArrayConverter.bytesToHexString(cipherSuites.getValue()))
                .append("\n  Supported Compression Methods: ")
                .append(ArrayConverter.bytesToHexString(compressions.getValue())).append("\n  Extensions: ");
        // Some ExtensionsTypes are not supported yet, so avoiding the
        // NULLPointerException needs to be done
        /**
         * for (ExtensionMessage e : extensions) { sb.append(e.toString()); }
         */
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
        ProtocolMessageHandler handler = new ClientHelloHandler(tlsContext);
        handler.setProtocolMessage(this);
        return handler;
    }
}
