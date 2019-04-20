package com.example.spring.slack.oauth2.token;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccessTokenResponce {

	@JsonProperty("access_token")
	String accessToken;

	@JsonProperty("token_type")
	String tokenType;

	@JsonProperty("expires_in")
	long expiresIn = 0;

	@JsonProperty("refresh_token")
	String refreshToken;

	@JsonProperty("scope")
	String scope;

	@JsonAnySetter
	Map<String, Object> attributes = new HashMap<>();

	@JsonIgnore
	public Set<String> getScopes() {
		if (Objects.isNull(scope)) {
			return Collections.emptySet();
		}
		return new HashSet<>(Arrays.asList(scope.split("[ ,]")));
	}

	@JsonIgnore
	public TokenType getOauthTokenType() {
		if (StringUtils.isEmpty(tokenType)) {
			return null;
		}
		return TokenType.BEARER;
	}

	public String toString() {
		return ToStringBuilder.reflectionToString(this);
	}

}