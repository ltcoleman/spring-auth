package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Stream;

@EnableResourceServer
@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}
}

@RestController
class PrincipalRestController {

	@RequestMapping("/user")
	Principal principal(Principal principal) {
		return principal;
	}
}

@Component
class AccountCLR implements CommandLineRunner {

	private final AccountRepository accountRepository;

	@Autowired
	public AccountCLR(AccountRepository accountRepository) {
		this.accountRepository = accountRepository;
	}

	@Override
	public void run(String... strings) throws Exception {
		Stream.of( "jlong,spring", "pwebb,boot", "dsyer,cloud")
				.map( s -> s.split(","))
				.forEach( tuple -> accountRepository.save(new Account( tuple[0], tuple[1], true)));

	}
}

@Configuration
@EnableAuthorizationServer
class OAuthConfiguration extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()");
		super.configure(security);
	}

	@Autowired AccountUserDetailsService userDetailsService;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
				.inMemory()
				.withClient("acme")
				.authorizedGrantTypes("password","authorization_code", "refresh_token")
				.refreshTokenValiditySeconds(3600 * 24)
				.scopes("openid","read")
				.autoApprove("openid")
				.accessTokenValiditySeconds(3600)
				.secret("acmesecret");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
				.authenticationManager(this.authenticationManager)
				.userDetailsService(this.userDetailsService);
	}
}

/*@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private AccountUserDetailsService userDetailsService;

	public WebSecurityConfig(){
		super();
	}

	@Autowired
	public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.anyRequest().authenticated()
				.and().formLogin().permitAll()
				.and().csrf().disable();
	}
}*/


class ABCUser extends User implements Serializable {

	private static final long serialVersionUID = 410L;
	private String memberId;

	public ABCUser(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities, String memberId) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		this.memberId = memberId;
	}

	public String getMemberId() {
		return memberId;
	}

	public void setMemberId(String memberId) {
		this.memberId = memberId;
	}
}

@Service
class AccountUserDetailsService implements UserDetailsService {

	private final AccountRepository accountRepository;

	@Autowired
	public AccountUserDetailsService(AccountRepository accountRepository) {
		this.accountRepository = accountRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String memberId = "IamAmemberIdforlookupandStuff";
		return this.accountRepository.findByUsername(username)
				.map(account -> new ABCUser(account.getUsername(),
						account.getPassword(),
						account.isActive(),
						account.isActive(),
						account.isActive(),
						account.isActive(),
						AuthorityUtils.createAuthorityList("ROLE_ADMIN","ROLE_USER"),
						memberId))
				.orElseThrow(() -> new UsernameNotFoundException("OH NOES!"));
	}
}

interface AccountRepository extends JpaRepository<Account, Long> {

	Optional<Account> findByUsername(String username);
}

@Entity
class Account {

	@Id
	@GeneratedValue
	private Long id;

	private String username;
	private String password;
	private boolean active;

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public boolean isActive() {
		return active;
	}

	public Account() {
		//why JPA why??
	}

	public Account(String username, String password, boolean active){
		this.username = username;
		this.password = password;
		this.active = active;
	}

	public Long getId() {
		return id;
	}

	@Override
	public String toString() {
		return "Account{" +
				"id=" + id +
				", username='" + username + '\'' +
				", password='" + password + '\'' +
				", active=" + active +
				'}';
	}
}