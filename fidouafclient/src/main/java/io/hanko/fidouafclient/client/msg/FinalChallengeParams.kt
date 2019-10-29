package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class FinalChallengeParams (
	val appID: String,
	val challenge: String,
	val facetID: String,
	val channelBinding: ChannelBinding
)
