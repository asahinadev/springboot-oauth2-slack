package com.example.spring.oauth2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoggingClientHttpRequestInterceptor
		implements ClientHttpRequestInterceptor {

	@Override
	public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
			throws IOException {

		log.debug("header   => {}", request.getHeaders());
		log.debug("body     => {}", new String(body, StandardCharsets.UTF_8));

		BufferingClientHttpResponseWrapper response;
		response = new BufferingClientHttpResponseWrapper(execution.execute(request, body));

		log.debug("status   => {}", response.getStatusCode());
		log.debug("response => {}", response.getBodyText());

		return response;
	}

}
