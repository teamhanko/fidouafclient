package io.hanko.fidouafclient.asm.msgs;

public enum StatusCode {

    UAF_ASM_STATUS_OK((short) 0x00),
    UAF_ASM_STATUS_ERROR((short) 0x01),
    UAF_ASM_STATUS_ACCESS_DENIED((short) 0x02),
    UAF_ASM_STATUS_USER_CANCELLED((short) 0x03),
    UAF_ASM_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT((short) 0x04),
    UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY((short) 0x09),
    UAF_ASM_STATUS_AUTHENTICATOR_DISCONNECTED((short) 0x0b),
    UAF_ASM_STATUS_USER_NOT_RESPONSIVE((short) 0x0e),
    UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES((short) 0x0f),
    UAF_ASM_STATUS_USER_LOCKOUT((short) 0x10),
    UAF_ASM_STATUS_USER_NOT_ENROLLED((short) 0x11);

    private final short ID;

    StatusCode(final short id) {
        this.ID = id;
    }

    public short getID() {
        return this.ID;
    }
}
