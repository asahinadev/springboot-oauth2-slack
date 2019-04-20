package com.example.spring.slack.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.example.spring.slack.oauth2.service.SlackUserService;
import com.example.spring.slack.oauth2.token.AccessTokenResponseClient;

@Configuration
@EnableWebSecurity
public class SecurityConfiguig
		extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web)
			throws Exception {
		super.configure(web);

		web.ignoring().antMatchers(
				// webjars
				"/webjars/**",
				// CSS ファイル
				"/css/**",
				// JavaScriptファイル
				"/js/**",
				// 画像ファイル
				"/img/**",
				// サウンドファイル
				"/sound/**",
				// WEB フォント
				"/font/**",
				"/fonts/**",
				// 外部ライブラリ
				"/exlib/**"
		/**/
		);
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		super.configure(auth);
	}

	@Override
	protected void configure(HttpSecurity http)
			throws Exception {
		super.configure(http);

		http.formLogin().disable();
		http.logout().disable();

		http.httpBasic().disable();

		http.csrf().disable();

		http.oauth2Login()

				// 認証エンドポイント
				.authorizationEndpoint()
				.and()

				// リダイレクトエンドポイント
				.redirectionEndpoint()
				.and()

				// トークンエンドポイント
				.tokenEndpoint()
				.accessTokenResponseClient(new AccessTokenResponseClient())
				.and()

				// ユーザー情報エンドポイント
				.userInfoEndpoint()
				.userService(userService());

	}

	private DelegatingOAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
		Map<String, Class<? extends OAuth2User>> customUser = new HashMap<>();

		List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();

		// Slack 専用
		userServices.add(new SlackUserService());

		// Custom UserService 
		if (customUser.isEmpty() == false) {
			userServices.add(new CustomUserTypesOAuth2UserService(customUser));
		}

		// Default UserService
		userServices.add(new DefaultOAuth2UserService());

		// 作成
		return new DelegatingOAuth2UserService<>(userServices);
	}

}
