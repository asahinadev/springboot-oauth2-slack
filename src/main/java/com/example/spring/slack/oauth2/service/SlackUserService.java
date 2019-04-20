package com.example.spring.slack.oauth2.service;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.example.spring.slack.oauth2.interceptor.LoggingClientHttpRequestInterceptor;
import com.example.spring.slack.oauth2.user.SlackUser;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SlackUserService
		implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	SlackUserRequestEntityConverter requestEntityConverter;
	RestTemplate restTemplate;

	/**
	 * Constructs a {@code CustomUserTypesOAuth2UserService} using the provided
	 * parameters.
	 *
	 * @param customUserTypes a {@code Map} of {@link OAuth2User} type(s) keyed
	 *                        by {@link ClientRegistration#getRegistrationId()
	 *                        Registration Id}
	 */
	public SlackUserService() {
		restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		restTemplate.setInterceptors(Arrays.asList(
				new LoggingClientHttpRequestInterceptor()));
		requestEntityConverter = new SlackUserRequestEntityConverter();
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");

		String registrationId = userRequest.getClientRegistration().getRegistrationId();
		log.debug("registrationId {}", registrationId);
		if (!Objects.equals(registrationId, "slack")) {
			return null;
		}
		log.debug("loadUser {}", userRequest);

		RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);
		ResponseEntity<? extends OAuth2User> response;

		try {
			log.debug("request => {}", request);
			response = this.restTemplate.exchange(request, SlackUser.class);
		} catch (RestClientException ex) {
			log.warn(ex.getMessage(), ex);

			OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
					"An error occurred while attempting to retrieve the UserInfo Resource: " + ex.getMessage(), null);

			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		OAuth2User oauth2User = response.getBody();

		return oauth2User;
	}

	class SlackUserRequestEntityConverter
			implements Converter<OAuth2UserRequest, RequestEntity<?>> {

		/**
		 * Returns the {@link RequestEntity} used for the UserInfo Request.
		 *
		 * @param userRequest the user request
		 * @return the {@link RequestEntity} used for the UserInfo Request
		 */
		@Override
		public RequestEntity<?> convert(OAuth2UserRequest userRequest) {

			ClientRegistration clientRegistration = userRequest.getClientRegistration();

			HttpMethod httpMethod = HttpMethod.POST;

			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
			headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
			headers.setContentLength(0);

			URI uri = UriComponentsBuilder
					.fromUriString(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
					.build()
					.toUri();

			Map<String, Object> body = new HashMap<>();
			body.putAll(userRequest.getAdditionalParameters());

			return new RequestEntity<>(body, headers, httpMethod, uri);
		}
	}

}