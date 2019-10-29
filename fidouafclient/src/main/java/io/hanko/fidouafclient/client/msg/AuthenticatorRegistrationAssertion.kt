package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class AuthenticatorRegistrationAssertion (
	val assertionScheme: String,
	val assertion: String,
	val tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?,
	val exts: List<Extension>?
)
