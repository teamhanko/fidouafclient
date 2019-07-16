package io.hanko.fidouafclient.asm.msgs;

public enum StatusCode {

    UAF_ASM_STATUS_OK((short) 0x00),
    UAF_ASM_STATUS_ERROR((short) 0x01),
    UAF_ASM_STATUS_ACCESS_DENIED((short) 0x02),
    UAF_ASM_STATUS_USER_CANCELLED((short) 0x03),
    UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY((short) 0x09);

    private final short ID;

    StatusCode(final short id) {
        this.ID = id;
    }

    public short getID() {
        return this.ID;
    }
}
