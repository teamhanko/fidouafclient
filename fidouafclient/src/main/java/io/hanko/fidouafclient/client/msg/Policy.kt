package io.hanko.fidouafclient.client.msg

import com.fasterxml.jackson.annotation.JsonProperty

class Policy (
		@JsonProperty(required = true) val accepted: List<List<MatchCriteria>>,
		val disallowed: List<MatchCriteria>? = null
)
