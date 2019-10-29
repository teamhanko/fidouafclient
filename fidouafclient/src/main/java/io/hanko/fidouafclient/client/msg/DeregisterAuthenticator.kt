package io.hanko.fidouafclient.client.msg;

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class DeregisterAuthenticator (
	val aaid: String,
	val keyID: String
)
