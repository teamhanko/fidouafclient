package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class Extension (
	val id: String,
	val data: String,
	val fail_if_unknown: Boolean
)
