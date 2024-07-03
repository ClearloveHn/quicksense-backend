package pro.quicksense.modules.util;


import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import pro.quicksense.modules.common.CommonConstant;
import pro.quicksense.modules.entity.User;

import java.util.Date;

@Component
public class JwtInterceptor implements HandlerInterceptor {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String path = request.getRequestURI();
        if ("/user/login".equals(path) || "/user/register".equals(path) || "/user/loginByEmail".equals(path)) {
            return true;
        }

        // Get the token from the request header
        String token = request.getHeader(CommonConstant.X_ACCESS_TOKEN);

        if (StringUtils.isBlank(token)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token is missing or has expired");
            return false;
        }

        try {
            // Verify the token
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();

            // Store the user information in the request attributes for subsequent use
            request.setAttribute("userId", claims.get("userId"));

            return true;
        } catch (JwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return false;
        }
    }

    public String generateToken(User user) {
        // Set token expiration time, here set to 1 day
        Date expiration = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000);

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("userId", user.getId())
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS512, "secret")  // todo For testing only, please use a different secret key in production
                .compact();
    }
}
