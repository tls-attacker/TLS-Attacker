package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlTransient;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.https.HttpsMessage;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({ Message.class, ProtocolMessage.class, HttpsMessage.class})
public abstract class Message<Self extends Message> extends ModifiableVariableHolder
        implements DataContainer<Self> {

    /**
     * content type
     */
    @XmlTransient
    protected ProtocolMessageType protocolMessageType;

    public boolean addToTypes(List<ProtocolMessageType> protocolMessageTypes) {
        return protocolMessageTypes.add(getProtocolMessageType());
    }

    public abstract String toCompactString();

    public abstract String toShortString();

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }
}
