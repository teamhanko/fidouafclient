package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class OperationHeader (
	val upv: Version,
	val op: Operation,
	val appID: String? = null,
	val serverData: String? = null,
	val exts: List<Extension>? = null
)
