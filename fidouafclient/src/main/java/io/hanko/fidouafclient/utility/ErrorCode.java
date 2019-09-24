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
    AUTHENTICATOR_ACCESS_DENIED((short) 0x0c),
    INVALID_TRANSACTION_CONTENT((short) 0x0d),
    USER_NOT_RESPONSIVE((short) 0x0e),
    INSUFFICIENT_AUTHENTICATOR_RESOURCES((short) 0x0f),
    USER_LOCKOUT((short) 0x10),
    USER_NOT_ENROLLED((short) 0x11),
    UNKNOWN((short) 0xFF);

    private final short ID;

    ErrorCode(final short id) {
        this.ID = id;
    }

    public short getID() {
        return this.ID;
    }
}
