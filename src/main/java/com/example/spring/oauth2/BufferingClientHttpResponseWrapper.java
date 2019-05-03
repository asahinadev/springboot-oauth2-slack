package com.example.spring.oauth2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.GZIPInputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StreamUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BufferingClientHttpResponseWrapper implements ClientHttpResponse {

	private final ClientHttpResponse response;

	@Nullable
	private byte[] body;

	BufferingClientHttpResponseWrapper(ClientHttpResponse response) {
		Assert.notNull(response, "ClientHttpResponse");
		log.debug("ClientHttpResponse {}", response);
		this.response = response;
	}

	@Override
	public HttpStatus getStatusCode() throws IOException {
		log.debug("status {}", response.getStatusCode());
		return this.response.getStatusCode();
	}

	@Override
	public int getRawStatusCode() throws IOException {
		log.debug("status {}", response.getRawStatusCode());
		return this.response.getRawStatusCode();
	}

	@Override
	public String getStatusText() throws IOException {
		log.debug("status {}", response.getStatusText());
		return this.response.getStatusText();
	}

	@Override
	public HttpHeaders getHeaders() {
		log.debug("header {}", response.getHeaders());
		return this.response.getHeaders();
	}

	@Override
	public InputStream getBody() throws IOException {
		if (this.body == null) {
			List<String> encoding = this.getHeaders().get(HttpHeaders.CONTENT_ENCODING);
			if (encoding == null || encoding.isEmpty()) {
				this.body = StreamUtils.copyToByteArray(this.response.getBody());
			} else if (encoding.get(0).equals("gzip")) {
				// GZIP
				this.body = StreamUtils.copyToByteArray(new GZIPInputStream(this.response.getBody()));
			} else {
				throw new IllegalStateException(encoding.get(0));
			}
		}
		log.debug("body {}", body);
		return new ByteArrayInputStream(this.body);
	}

	public String getBodyText() throws IOException {
		getBody();
		return new String(body, StandardCharsets.UTF_8);
	}

	@Override
	public void close() {
		this.response.close();
	}

}
