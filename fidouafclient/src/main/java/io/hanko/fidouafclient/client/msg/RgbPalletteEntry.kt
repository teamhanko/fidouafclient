package io.hanko.fidouafclient.client.msg;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class RgbPalletteEntry (
    val r: Short,
    val g: Short,
    val b: Short
)
