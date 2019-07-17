# FIDO UAF Client & Authenticator
[![Build Status](https://travis-ci.org/teamhanko/fidouafclient.svg?branch=master)](https://travis-ci.org/teamhanko/fidouafclient)

FIDO UAF Client & Authenticator for Android by Hanko.

## Installation

### Gradle

`implementation 'io.hanko:fidouafclient:<latest-version>'`

## Basic Usage
TODO

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