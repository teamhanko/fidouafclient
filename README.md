# FIDO UAF Client & Authenticator
[![Build Status](https://travis-ci.org/teamhanko/fidouafclient.svg?branch=master)](https://travis-ci.org/teamhanko/fidouafclient)
[![Download](https://api.bintray.com/packages/hanko/android/fidouafclient/images/download.svg)](https://bintray.com/hanko/android/fidouafclient/_latestVersion)

FIDO UAF Client & Authenticator for Android by Hanko.

**Supported UAF Versions:** 1.0

> For more information on how FIDO UAF works, see [FIDO Alliance](https://fidoalliance.org/specifications/download/).

## Installation

The package is distributed through JCenter.

### Gradle

`implementation 'io.hanko:fidouafclient:<latest-version>'`

## Basic Usage

### Call FIDO Client

```java
Intent intent = new Intent(context, io.hanko.fidouafclient.client.MainActivity.class);
intent.setType("application/fido.uaf_client+json");
intent.putExtra("UAFIntentType", "UAF_OPERATION");
intent.putExtra("channelBindings", "{}");
intent.putExtra("message", "<fido-uaf-request>");

startActivityForResult(intent, REQUEST_CODE);
```

The `<fido-uaf-request>` must be in format defined in [UAFMessage](https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#uafmessage-dictionary).

#### Example of UAFMessage
```json
{
	"uafProtocolMessage": "<uaf-protocol-message-string>"
}
```

### Result of FIDO Client

```java
protected void onActivityResult(int requestCode, int resultCode, Intent data) {
	if(resultCode == RESULT_OK && requestCode == REQUEST_CODE) {
		short errorCode = data.getShortExtra("errorCode", (short) 0xFF);
		if(errorCode == 0x00) { // erroCode 0x00 means success
			try {
				JSONObject jsonObject = new JSONObject(data.getStringExtra("message"));
				String uafResponse = jsonObject.getString("uafProtocolMessage");
				// verify uafResponse
			} catch(JSONException ex) {
				// TODO
			}
		} else {
			// some error occured, use errorCode for determination
		}
	}
}
```

> **Note:** All available ErrorCodes can be found [here](https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-client-api-transport-v1.0-ps-20141208.html#idl-def-ErrorCode).

## Limitations

This client is not complete and have the following limitations. But if you only want an FIDO UAF Client and Authenticator to Register and Authenticate a user you are ready to go.

- The client only uses its build in authenticators
- The client does not return Authenticators on `DISCOVER`
- The client does not check the policy on `CHECK_POLICY`, but returns always `NO_ERROR`
- The build in authenticators are not usable from an other FIDO client

# License

	Copyright 2019 Hanko

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.