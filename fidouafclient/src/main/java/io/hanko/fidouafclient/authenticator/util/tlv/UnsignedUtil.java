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

package io.hanko.fidouafclient.authenticator.util.tlv;

public class UnsignedUtil {

	/**
	 * Take the two bytes of the integer and encode it in little endian
	 * @param id
	 * @return
	 */
	public static byte[] encodeInt(int id) {

		byte[] bytes = new byte[2];
		bytes[0] = (byte)(id&0x00ff);
		bytes[1] = (byte)((id&0xff00)>>8);
		return bytes;
	}

	/**
	 * Take the four bytes of the integer and encode it in little endian
	 * @param id
	 * @return
	 */
	public static byte[] encodeInt32(int id) {

		byte[] bytes = new byte[4];
		bytes[0] = (byte)(id&0x000000ff);
		bytes[1] = (byte)((id&0x0000ff00)>>8);
		bytes[2] = (byte)((id&0x00ff0000)>>16);
		bytes[3] = (byte)((id&0xff000000)>>24);
		return bytes;
	}
}
