package io.hanko.fidouafclient.client.msg.client

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class UAFMessage (
	val uafProtocolMessage: String
)
