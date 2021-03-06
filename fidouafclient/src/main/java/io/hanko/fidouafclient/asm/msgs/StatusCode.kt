package io.hanko.fidouafclient.asm.msgs

enum class StatusCode(val id: Short) {

    UAF_ASM_STATUS_OK(0x00),
    UAF_ASM_STATUS_ERROR(0x01),
    UAF_ASM_STATUS_ACCESS_DENIED(0x02),
    UAF_ASM_STATUS_USER_CANCELLED(0x03),
    UAF_ASM_STATUS_CANNOT_RENDER_TRANSACTION_CONTENT(0x04),
    UAF_ASM_STATUS_KEY_DISAPPEARED_PERMANENTLY(0x09),
    UAF_ASM_STATUS_AUTHENTICATOR_DISCONNECTED(0x0b),
    UAF_ASM_STATUS_USER_NOT_RESPONSIVE(0x0e),
    UAF_ASM_STATUS_INSUFFICIENT_AUTHENTICATOR_RESOURCES(0x0f),
    UAF_ASM_STATUS_USER_LOCKOUT(0x10),
    UAF_ASM_STATUS_USER_NOT_ENROLLED(0x11);
}
