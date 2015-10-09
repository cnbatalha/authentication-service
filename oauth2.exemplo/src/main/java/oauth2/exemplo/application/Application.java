package oauth2.exemplo.application;

import java.io.File;
import java.util.Arrays;

import oauth2.exemplo.application.oauth.ClientAndUserDetailsService;
import oauth2.exemplo.application.oauth.User;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//Tell Spring to automatically inject any dependencies that are marked in
//our classes with @Autowired
@EnableAutoConfiguration
// Tell Spring that this object represents a Configuration for the
// application
@Configuration
// Tell Spring to go and scan our controller package (and all sub packages) to
// find any Controllers or other components that are part of our applciation.
// Any class in this package that is annotated with @Controller is going to be
// automatically discovered and connected to the DispatcherServlet.
@ComponentScan(basePackages = { "oauth2.exemplo" }, excludeFilters = { @Filter(type = FilterType.ANNOTATION, value = Configuration.class) })
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Configuration
	@EnableWebSecurity
	protected static class WebSecurityConfiguration extends
			WebSecurityConfigurerAdapter {

		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		protected void registerAuthentication(
				final AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(userDetailsService);
		}
	}

	/**
	 * This method is used to configure who is allowed to access which parts of
	 * our resource server (i.e. the "/video" endpoint)
	 */
	@Configuration
	@EnableResourceServer
	protected static class ResourceServer extends
			ResourceServerConfigurerAdapter {

		// This method configures the OAuth scopes required by clients to access
		// all of the paths in the video service.
		@Override
		public void configure(HttpSecurity http) throws Exception {

			http.csrf().disable();

			http.authorizeRequests()
				.antMatchers("/oauth/token").anonymous()
				.antMatchers("/uaa", "/uaa/**").permitAll();
			

			// If you were going to reuse this class in another
			// application, this is one of the key sections that you
			// would want to change

			// Require all GET requests to have client "read" scope
			http.authorizeRequests().antMatchers(HttpMethod.GET, "/**")
					.access("#oauth2.hasScope('read')");

			// Require all other requests to have "write" scope
			http.authorizeRequests().antMatchers("/**")
					.access("#oauth2.hasScope('write')");
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends
			AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		// A data structure used to store both a ClientDetailsService and a
		// UserDetailsService
		private ClientAndUserDetailsService combinedService_;

		public OAuth2Config() throws Exception {

			// If you were going to reuse this class in another
			// application, this is one of the key sections that you
			// would want to change

			// Create a service that has the credentials for all our clients
			ClientDetailsService csvc = new InMemoryClientDetailsServiceBuilder()
					// Create a client that has "read" and "write" access to the
					// video service
					.withClient("mobile")
					.authorizedGrantTypes("password")
					.authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
					.scopes("read", "write")
					//.resourceIds("uaa")
					.and()
					// Create a second client that only has "read" access to the
					// video service
					.withClient("mobileReader")
					.authorizedGrantTypes("password")
					.authorities("ROLE_CLIENT").scopes("read")
					//.resourceIds("uaa")
					.accessTokenValiditySeconds(3600)
					.and().build();

			// Create a series of hard-coded users.
			UserDetailsService svc = new InMemoryUserDetailsManager(
					Arrays.asList(
							User.create("admin", "pass", "ADMIN", "USER"),
							User.create("user0", "pass", "USER"),
							User.create("user1", "pass", "USER"),
							User.create("user2", "pass", "USER"),
							User.create("user3", "pass", "USER"),
							User.create("user4", "pass", "USER"),
							User.create("user5", "pass", "USER")));

			// Since clients have to use BASIC authentication with the client's
			// id/secret,
			// when sending a request for a password grant, we make each client
			// a user
			// as well. When the BASIC authentication information is pulled from
			// the
			// request, this combined UserDetailsService will authenticate that
			// the
			// client is a valid "user".
			combinedService_ = new ClientAndUserDetailsService(csvc, svc);
		}

		// @Override
		// public void configure(AuthorizationServerEndpointsConfigurer
		// endpoints)
		// throws Exception {
		//
		// endpoints.authenticationManager(authenticationManager);
		// }

		// @Override
		// public void configure(ClientDetailsServiceConfigurer clients)
		// throws Exception {
		//
		// clients.inMemory()
		// .withClient("username")
		// .secret("acmesecret")
		// .authorizedGrantTypes("authorization_code",
		// "refresh_token", "password").scopes("openid")
		// .autoApprove(new String[] { "openid" });
		// }

		/**
		 * Return the list of trusted client information to anyone who asks for
		 * it.
		 */
		@Bean
		public ClientDetailsService clientDetailsService() throws Exception {
			return combinedService_;
		}

		/**
		 * Return all of our user information to anyone in the framework who
		 * requests it.
		 */
		@Bean
		public UserDetailsService userDetailsService() {
			return combinedService_;
		}

		/**
		 * This method tells our AuthorizationServerConfigurerAdapter to use the
		 * delegated AuthenticationManager to process authentication requests.
		 */
		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints)
				throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}

		/**
		 * This method tells the AuthorizationServerConfigurerAdapter to use our
		 * self-defined client details service to authenticate clients with.
		 */
		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			clients.withClientDetails(clientDetailsService());
		}

		
	}

}
