/*
 * Copyright 2012-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.buildpack.platform.docker.configuration;

import com.fasterxml.jackson.core.JsonProcessingException;

import org.springframework.boot.buildpack.platform.json.SharedObjectMapper;
import org.springframework.util.Base64Utils;

/**
 * {@link DockerRegistryAuthentication} that uses a Base64 encoded auth header value based
 * on the JSON created from the instance.
 *
 * @author Scott Frederick
 */
class JsonEncodedDockerRegistryAuthentication implements DockerRegistryAuthentication {

	private String authHeader;

	private String cnbAuthHeader;

	@Override
	public String getAuthHeader() {
		return this.authHeader;
	}

	@Override
	public String getCNBAuthHeader() {
		return this.cnbAuthHeader;
	}

	protected void createAuthHeader() {
		try {
			this.authHeader = Base64Utils.encodeToUrlSafeString(SharedObjectMapper.get().writeValueAsBytes(this));
		}
		catch (JsonProcessingException ex) {
			throw new IllegalStateException("Error creating Docker registry authentication header", ex);
		}
	}

	/**
	 * NOTE: Lifecycle currently doesn't support identitytokens for authentication,
	 * 		 which means the auth header can only be created with username and password
	 * 		 right now.
	 * 
	 * @see https://github.com/buildpacks/lifecycle/blob/main/auth/env_keychain.go
	 *      authConfigToHeader()
	 * 
	 * TODO: Check if Lifecycle provides a better method of registry authentication
	 * 
	 * @see https://github.com/buildpacks/spec/blob/main/platform.md#registry-authentication
	 * 
	 */
	protected void createCNBAuthHeader(String username, String password) {
		this.cnbAuthHeader = String.format("Basic %s", Base64Utils.encodeToString(String.format("%s:%s", username, password).getBytes()));
	}

}
