package com.example.spring.slack.oauth2.token;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
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

import com.example.spring.slack.oauth2.interceptor.LoggingClientHttpRequestInterceptor;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AccessTokenResponseClient
		implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

	private RestTemplate restTemplate;

	public AccessTokenResponseClient() {
		this.restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(),
				new MappingJackson2HttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		this.restTemplate.setInterceptors(Arrays.asList(
				new LoggingClientHttpRequestInterceptor()));
		this.restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
	}

	public AccessTokenResponseClient(RestTemplate client) {
		this.restTemplate = client;
	}

	public OAuth2AccessTokenResponse getTokenResponse(
			OAuth2AuthorizationCodeGrantRequest request)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = request.getClientRegistration();
		OAuth2AuthorizationExchange authorization = request.getAuthorizationExchange();
		ProviderDetails provider = clientRegistration.getProviderDetails();

		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

		parameters.add("grant_type", clientRegistration.getAuthorizationGrantType().getValue());
		parameters.add("code", authorization.getAuthorizationResponse().getCode());
		parameters.add("redirect_uri", authorization.getAuthorizationRequest().getRedirectUri());

		// 通常は設定されていたら [ ] 区切りで設定する
		if (request.getClientRegistration().getScopes() != null
				&& !request.getClientRegistration().getScopes().isEmpty()) {
			parameters.add("scope", String.join(" ", request.getClientRegistration().getScopes()));
		}

		log.debug("parameters => {}", parameters);

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON_UTF8));

		switch (clientRegistration.getRegistrationId()) {

		case "dropbox":
			// Basic 認証
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
			break;

		default:
			// Form 認証
			parameters.add("client_id", clientRegistration.getClientId());
			parameters.add("client_secret", clientRegistration.getClientSecret());
			break;
		}

		String uri = provider.getTokenUri();

		ResponseEntity<AccessTokenResponce> response = restTemplate.exchange(
				uri,
				HttpMethod.POST,
				new HttpEntity<>(parameters, headers),
				AccessTokenResponce.class);

		log.debug("{}", response);

		AccessTokenResponce token = response.getBody();

		Set<String> scopes = token.getScopes().isEmpty()
				? authorization.getAuthorizationRequest().getScopes()
				: token.getScopes();

		TokenType tokenType = token.getOauthTokenType();

		switch (clientRegistration.getRegistrationId()) {

		case "slack":
		case "linkedin":
			tokenType = TokenType.BEARER;
			break;

		default:
			break;

		}

		long expiresIn = token.getExpiresIn();
		if (expiresIn == 0) {
			expiresIn = 30000;
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		switch (clientRegistration.getRegistrationId()) {

		// ユーザー検索のパラメーター設定
		case "dropbox":
			additionalParameters.put("account_id", token.getAttributes().get("account_id"));
			break;

		default:
			break;

		}

		log.debug("access_token {}, token_type {}", token.getAccessToken(), tokenType);

		return OAuth2AccessTokenResponse.withToken(
				token.getAccessToken())
				.tokenType(tokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.additionalParameters(additionalParameters)
				.build();
	}
}