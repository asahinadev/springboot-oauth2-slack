package com.example.spring.slack.oauth2.user;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@SuppressWarnings("serial")
public class SlackUser
		implements OAuth2User, Serializable {

	@JsonProperty("ok")
	boolean ok;

	@JsonProperty("error")
	String error;

	@JsonProperty("team")
	Map<String, Object> team = new HashMap<>();

	@JsonProperty("user")
	Map<String, Object> user = new HashMap<>();

	@JsonAnySetter
	Map<String, Object> extra = new HashMap<>();

	@Override
	public String getName() {
		return String.valueOf(getUser().get("id"));
	}

	public String getEmail() {
		return String.valueOf(getUser().get("email"));
	}

	@Override
	public List<GrantedAuthority> getAuthorities() {
		return Arrays.asList(
				new OAuth2UserAuthority("USER", getAttributes()),
				new SimpleGrantedAuthority("USER"));
	}

	@Override
	public Map<String, Object> getAttributes() {

		Map<String, Object> attributes = new HashMap<>(extra);

		attributes.put("team", getTeam());
		attributes.put("user", getUser());

		return Collections.unmodifiableMap(attributes);
	}

	@Override
	public String toString() {
		return getAttributes().toString();
	}
}
