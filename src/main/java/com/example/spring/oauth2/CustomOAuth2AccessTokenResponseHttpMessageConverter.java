package com.example.spring.oauth2;

import java.util.*;

import org.springframework.http.*;
import org.springframework.http.converter.*;
import org.springframework.security.oauth2.core.OAuth2AccessToken.*;
import org.springframework.security.oauth2.core.endpoint.*;
import org.springframework.security.oauth2.core.http.converter.*;

import com.fasterxml.jackson.databind.*;

import lombok.extern.slf4j.*;

@Slf4j
public class CustomOAuth2AccessTokenResponseHttpMessageConverter
	extends OAuth2AccessTokenResponseHttpMessageConverter {

	private static final String ERROR = "An error occurred reading the OAuth 2.0 Access Token Response: ";
	private static final String TOKEN_MSG = "必須パラメーター [{}] が未設定のため RFC 仕様上標準の値である [{}] を設定しました。";

	protected OAuth2AccessTokenResponse readInternal(
			Class<? extends OAuth2AccessTokenResponse> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {

		try {
			Map<String, String> tokenResponseParameters = new ObjectMapper()
					.readerFor(new MapTypeReference()).readValue(inputMessage.getBody());

			log.debug("tokenResponseParameters : {}", tokenResponseParameters);

			if (!tokenResponseParameters.containsKey("token_type")) {
				log.warn(TOKEN_MSG, "token_type", TokenType.BEARER.getValue());
				tokenResponseParameters.put("token_type", TokenType.BEARER.getValue());
			}

			return this.tokenResponseConverter.convert(tokenResponseParameters);
		} catch (Exception ex) {
			throw new HttpMessageNotReadableException(ERROR + ex.getMessage(), ex, inputMessage);
		}
	}
}