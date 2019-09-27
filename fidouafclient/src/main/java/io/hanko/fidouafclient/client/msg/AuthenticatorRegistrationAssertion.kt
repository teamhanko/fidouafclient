package io.hanko.fidouafclient.client.msg

class AuthenticatorRegistrationAssertion (
	val assertionScheme: String,
	val assertion: String,
	val tcDisplayPNGCharacteristics: DisplayPNGCharacteristicsDescriptor?,
	val exts: List<Extension>?
)
