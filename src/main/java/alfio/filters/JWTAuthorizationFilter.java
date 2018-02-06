package alfio.filters;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Created on 2/5/2018.
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    @Value("${rewards.auth.key}")
    private String key;

    public JWTAuthorizationFilter(AuthenticationManager authManager, String key) {
        super(authManager);
        this.key = key;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
        HttpServletResponse res,
        FilterChain chain) throws IOException, ServletException {

        String tokenParam = req.getParameter(JWTAuthenticationProvider.AUTH);

        if (tokenParam == null) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
        Authentication authResult = getAuthenticationManager()
            .authenticate(authentication);

        SecurityContextHolder.getContext().setAuthentication(authResult);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getParameter(JWTAuthenticationProvider.AUTH);
        if (token != null) {
            // parse the token.
            String user = Jwts.parser()
                .setSigningKey(key.getBytes())
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, token, new ArrayList<>());
            }
        }
        return null;
    }
}
