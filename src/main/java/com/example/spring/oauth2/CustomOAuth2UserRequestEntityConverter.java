package com.example.spring.oauth2;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomOAuth2UserRequestEntityConverter
		extends OAuth2UserRequestEntityConverter {

	@Override
	public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		AuthenticationMethod authenticationMethod = clientRegistration.getProviderDetails().getUserInfoEndpoint()
				.getAuthenticationMethod();

		HttpMethod httpMethod = HttpMethod.GET;
		if (AuthenticationMethod.FORM.equals(authenticationMethod)) {
			httpMethod = HttpMethod.POST;
		} else if (new AuthenticationMethod("json").equals(authenticationMethod)) {
			httpMethod = HttpMethod.POST;
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		URI uri = UriComponentsBuilder
				.fromUriString(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
				.build()
				.toUri();

		log.debug("{}", userRequest.getAdditionalParameters());

		RequestEntity<?> request;

		MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
		Object body = formParameters;

		switch (clientRegistration.getRegistrationId()) {
		case "dropbox":
			formParameters.add("account_id", userRequest.getAdditionalParameters().get("account_id").toString());
			break;

		default:
			break;
		}

		if (AuthenticationMethod.FORM.equals(authenticationMethod)) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
			formParameters.add(OAuth2ParameterNames.ACCESS_TOKEN, userRequest.getAccessToken().getTokenValue());
		} else if (AuthenticationMethod.QUERY.equals(authenticationMethod)) {
			request = new RequestEntity<>(headers, httpMethod, uri);
		} else if (new AuthenticationMethod("json").equals(authenticationMethod)) {
			headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
			headers.setContentType(MediaType.APPLICATION_JSON_UTF8);

			Map<String, Object> json = new HashMap<>();
			for (Entry<String, List<String>> entry : formParameters.entrySet()) {
				String key = entry.getKey();
				List<String> val = entry.getValue();

				if (val.isEmpty()) {
					json.put(key, null);
				} else if (val.size() == 1) {
					json.put(key, val.get(0));
				} else {
					json.put(key, val);
				}
			}
			body = json;

		} else {
			headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
		}
		request = new RequestEntity<>(body, headers, httpMethod, uri);

		return request;
	}
}