/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.hanko.fidouafclient.client.msg;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Set;

import io.hanko.fidouafclient.authenticator.config.AuthenticatorConfig;
import io.hanko.fidouafclient.authenticator.msgs.Authenticator;
import io.hanko.fidouafclient.utility.Preferences;

public class MatchCriteria {
	public String[] aaid;
	public String[] vendorID;
	public String[] keyIDs;
	public long userVerification;
	public int keyProtection;
	public int matcherProtection;
	public long attachmentHint;
	public int tcDisplay;
	public int[] authenticationAlgorithms;
	public String[] assertionSchemes;
	public int[] attestationTypes;
	public int authenticatorVersion;
	public Extension[] exts;

	public Boolean matchesAuthenticator(Authenticator authenticator, Context context, String appId) {
		if ((aaid != null && !aaid[0].equals(authenticator.aaid)) || (aaid!= null && aaid.length != 1)) {
			return false;
		}

		if ((vendorID != null && !vendorID[0].equals(authenticator.aaid.split("#")[0])) || (vendorID != null && vendorID.length != 1)) {
			return false;
		}

		if (userVerification != 0 && userVerification != authenticator.userVerification) {
			return false;
		}

		if (keyProtection != 0 && keyProtection != authenticator.keyProtection) {
			return false;
		}

		if (matcherProtection != 0 && matcherProtection != authenticator.matcherProtection) {
			return false;
		}

		if (attachmentHint != 0 && attachmentHint != authenticator.attachmentHint) {
			return false;
		}

		if (tcDisplay != 0 && !(tcDisplay == 0x01 || tcDisplay == 0x02 || tcDisplay == 0x03)) {
			return false;
		}

		if ((authenticationAlgorithms != null && authenticationAlgorithms.length != 1) || (authenticationAlgorithms != null && authenticationAlgorithms[0] != authenticator.authenticationAlgorithm)) {
			return false;
		}

		if ((assertionSchemes != null && assertionSchemes.length != 1) || (assertionSchemes != null && !assertionSchemes[0].equals(authenticator.assertionScheme))) {
			return false;
		}

		if ((attestationTypes != null && attestationTypes.length != 1) || (attestationTypes != null && attestationTypes[0] != authenticator.attestationTypes[0])) {
			return false;
		}

		if (keyIDs != null && !isKeyIdRegisteredForAuthenticator(context, keyIDs, authenticator.aaid, appId)) {
			return false;
		}

		return true;
	}

	private boolean isKeyIdRegisteredForAuthenticator(Context context, String[] keyIDs, String aaid, String appId) {
		String preference = Preferences.FINGERPRINT_PREFERENCE;
		if (aaid.equals(AuthenticatorConfig.authenticator_lockscreen.aaid)) {
			preference = Preferences.LOCKSCREEN_PREFERENCE;
		}
		SharedPreferences sharedPreferences = Preferences.create(context, preference);
		Set<String> registeredKeyIds = Preferences.getParamSet(sharedPreferences, appId);

		boolean isOneKeyIdRegistered = false;
		for (String keyId : keyIDs) {
			if (registeredKeyIds.contains(keyId)) {
				isOneKeyIdRegistered = true;
				break;
			}
		}

		return isOneKeyIdRegistered;
	}
}
