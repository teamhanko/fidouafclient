package io.hanko.fidouafclient.utility;

public enum ErrorCode {

    NO_ERROR((short) 0x00),
    WAIT_USER_ACTION((short) 0x01),
    INSECURE_TRANSPORT((short) 0x02),
    USER_CANCELLED((short) 0x03),
    UNSUPPORTED_VERSION((short) 0x04),
    NO_SUITABLE_AUTHENTICATOR((short) 0x05),
    PROTOCOL_ERROR((short) 0x06),
    UNTRUSTED_FACET_ID((short) 0x07),
    KEY_DISAPPEARED_PERMANENTLY((short) 0x09),
    UNKNOWN((short) 0xFF);

    private final short ID;

    ErrorCode(final short id) {
        this.ID = id;
    }

    public short getID() {
        return this.ID;
    }
}
