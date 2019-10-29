package io.hanko.fidouafclient.client.msg;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class Transaction (
	val contentType: String,
	val content: String,
	val tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?
)
