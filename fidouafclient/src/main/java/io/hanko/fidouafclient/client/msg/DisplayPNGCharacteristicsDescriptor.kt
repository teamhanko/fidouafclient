package io.hanko.fidouafclient.client.msg;

class DisplayPNGCharacteristicsDescriptor (
	val width: Long,
	val height: Long,
	val bitDepth: String,
	val colorType: String,
	val compression: String,
	val filter: String,
	val interlace: String,
	val plte: List<RgbPalletteEntry>?
)
