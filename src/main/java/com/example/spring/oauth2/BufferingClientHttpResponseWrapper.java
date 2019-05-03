package com.example.spring.oauth2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
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
		this.response = response;
	}

	@Override
	public HttpStatus getStatusCode() throws IOException {
		log.debug("status {}", response.getStatusCode());
		return this.response.getStatusCode();
	}

	@Override
	public int getRawStatusCode() throws IOException {
		return this.response.getRawStatusCode();
	}

	@Override
	public String getStatusText() throws IOException {
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
			} else {
				switch (encoding.get(0)) {

				case "gzip":
				case "x-gzip":
					// LZ77
					this.body = StreamUtils.copyToByteArray(new GZIPInputStream(this.response.getBody()));
					break;

				case "identity":
				case "br":
					log.warn("現在未実装です。");
					throw new UnsupportedEncodingException(encoding.get(0));

				case "compress":
				default:
					log.error("実装予定はありません");
					throw new UnsupportedEncodingException(encoding.get(0));
				}
			}
		}
		log.debug("body {}", new String(body, StandardCharsets.UTF_8));
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
