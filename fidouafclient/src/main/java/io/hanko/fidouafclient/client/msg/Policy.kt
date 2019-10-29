package io.hanko.fidouafclient.client.msg

import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
class Policy (
		val accepted: List<List<MatchCriteria>>,
		val disallowed: List<MatchCriteria>? = null
)
