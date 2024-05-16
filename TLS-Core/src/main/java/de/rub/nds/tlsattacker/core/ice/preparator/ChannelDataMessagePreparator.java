package de.rub.nds.tlsattacker.core.ice.preparator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ChannelDataMessagePreparator extends IceMessagePreparator<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessagePreparator(Chooser chooser, ChannelDataMessage object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        getObject().setChannelNumber(chooser.getIceChooser().getTurnDataChannel());
        getObject().setData(getObject().getDataConfig());
        getObject().setMessageLength(getObject().getData().getValue().length);
        if (chooser.getConfig().getIceConfig().isPadUdpChannelDataMessages()) {
            int paddingLength = (IceByteLengths.DATA_CHANNEL_ALIGNMENT - (getObject().getMessageLength().getValue())
                    % IceByteLengths.DATA_CHANNEL_ALIGNMENT) % IceByteLengths.DATA_CHANNEL_ALIGNMENT;
            if (paddingLength < 0) {
                paddingLength = 0;
            }
            LOGGER.debug("Padding length: {}", paddingLength);
            getObject().setPadding(new byte[paddingLength]);
        } else {
            getObject().setPadding(new byte[0]);
        }
    }

}
