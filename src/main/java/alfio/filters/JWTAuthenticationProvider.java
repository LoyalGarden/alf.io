package alfio.filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * Created on 2/5/2018.
 */
@Service
public class JWTAuthenticationProvider implements AuthenticationProvider {

    public static final String AUTH = "auth";

    @Value("${oauth.auth.url}")
    private String authUrl;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String token = authentication.getCredentials().toString();
        RestTemplate restTemplate = new RestTemplate();
        String requestString = String.format("%s?%s=%s", authUrl, AUTH, token);


        ResponseEntity<String> response  = restTemplate.getForEntity(requestString, String.class);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root;
        try {
            root = mapper.readTree(response.getBody());
        } catch (IOException e) {
            throw new RuntimeException(e);

        }
        JsonNode authorities = root.path("authorities");

        List<SimpleGrantedAuthority> granded  = new ArrayList<>();
        for (JsonNode authority : authorities) {
            granded.add(new SimpleGrantedAuthority(authority.path("authority").asText()));
        }
        return new UsernamePasswordAuthenticationToken(name, token, granded);

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(
            UsernamePasswordAuthenticationToken.class);
    }

}
