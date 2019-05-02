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
import org.springframework.util.StreamUtils;

public class BufferingClientHttpResponseWrapper implements ClientHttpResponse {

	private final ClientHttpResponse response;

	@Nullable
	private byte[] body;

	BufferingClientHttpResponseWrapper(ClientHttpResponse response) {
		this.response = response;
	}

	@Override
	public HttpStatus getStatusCode() throws IOException {
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
		return this.response.getHeaders();
	}

	@Override
	public InputStream getBody() throws IOException {
		if (this.body == null) {
			System.out.println(getHeaders());
			// [Cache-Control:"private", Content-Type:"application/json; charset=utf-8", Content-Encoding:"gzip", Access-Control-Allow-Origin:"*", Access-Control-Allow-Methods:"GET, POST", Access-Control-Allow-Credentials:"false", X-Content-Type-Options:"nosniff", Date:"Sat, 20 Apr 2019 14:01:13 GMT", Content-Length:"365"]
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
