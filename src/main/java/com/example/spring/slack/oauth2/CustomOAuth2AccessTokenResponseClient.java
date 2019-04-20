package com.example.spring.slack.oauth2;

import java.util.Arrays;
import java.util.Set;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomOAuth2AccessTokenResponseClient
		implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	private RestTemplate client;

	public CustomOAuth2AccessTokenResponseClient() {
		this.client = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		this.client.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
	}

	public CustomOAuth2AccessTokenResponseClient(RestTemplate client) {
		this.client = client;
	}

	public OAuth2AccessTokenResponse getTokenResponse(
			OAuth2AuthorizationCodeGrantRequest request)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = request.getClientRegistration();
		OAuth2AuthorizationExchange authorization = request.getAuthorizationExchange();
		ProviderDetails provider = clientRegistration.getProviderDetails();

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

		parameters.add("grant_type", clientRegistration.getAuthorizationGrantType().getValue());
		parameters.add("client_id", clientRegistration.getClientId());
		parameters.add("client_secret", clientRegistration.getClientSecret());
		parameters.add("code", authorization.getAuthorizationResponse().getCode());
		parameters.add("redirect_uri", authorization.getAuthorizationRequest().getRedirectUri());
		// parameters.add("scope", String.join(" ", request.getClientRegistration().getScopes()));

		log.debug("parameters => {}", parameters);

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		String uri = provider.getTokenUri();

		ResponseEntity<AccessResponse> response = client.exchange(
				uri,
				HttpMethod.POST,
				new HttpEntity<>(parameters, headers),
				AccessResponse.class);

		AccessResponse accessResponse = response.getBody();

		Set<String> scopes = accessResponse.getScopes().isEmpty()
				? authorization.getAuthorizationRequest().getScopes()
				: accessResponse.getScopes();

		TokenType tokenType = accessResponse.getOauthTOkenType();

		switch (clientRegistration.getRegistrationId()) {

		case "linkedin":
			tokenType = TokenType.BEARER;
			break;

		default:
			break;

		}
		long expiresIn = accessResponse.getExpiresIn();
		if (expiresIn == 0) {
			expiresIn = 3000;
		}

		return OAuth2AccessTokenResponse.withToken(
				accessResponse.getAccessToken())
				.tokenType(tokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.build();
	}
}
