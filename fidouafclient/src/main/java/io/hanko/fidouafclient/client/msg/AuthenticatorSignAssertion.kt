package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class AuthenticatorSignAssertion (
	val assertionScheme: String,
	val assertion: String,
	val exts: List<Extension>?
)
