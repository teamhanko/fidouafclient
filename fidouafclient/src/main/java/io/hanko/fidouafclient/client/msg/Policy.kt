package io.hanko.fidouafclient.client.msg;

class Policy (
	val accepted: List<List<MatchCriteria>>,
	val disallowed: List<MatchCriteria>?
)
