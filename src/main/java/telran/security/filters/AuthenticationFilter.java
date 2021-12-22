package telran.security.filters;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;
import telran.accountservise.dao.UserMongoRepository;
import telran.accountservise.model.User;
import telran.security.SessionService;
import telran.security.context.SecurityContext;
import telran.security.context.UserProfile;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Base64;
import java.util.Optional;

@Service
@Order(10)
public class AuthenticationFilter implements Filter {

    UserMongoRepository repository;
    SecurityContext securityContext;
    SessionService sessionService;

    @Autowired
    public AuthenticationFilter(UserMongoRepository repository, SecurityContext securityContext, SessionService sessionService) {
        this.repository = repository;
        this.securityContext = securityContext;
        this.sessionService = sessionService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (checkEndPoints(request.getServletPath(), request.getMethod())) {
            String token = request.getHeader("Authorization");
            String sessionId = request.getSession().getId();
            User userAccount = sessionService.getUser(sessionId);

            if (token == null && userAccount == null || sessionId == null){
                response.sendError(401, "Header Authorization not fond");
                return;
            }

            if (token != null) {
                String[] credentials = getCredential(token).orElse(null);
                if (credentials == null || credentials.length < 2) {
                    response.sendError(401, "Token not valid");
                    return;
                }
                userAccount = repository.findById(credentials[0]).orElse(null);
                if (userAccount == null) {
                    response.sendError(401, "User not valid");
                    return;
                }
                if (!BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
                    response.sendError(401, "User or pass not a valid");
                    return;
                }
//                request = new WrappedRequest(request, credentials[0]);
                sessionService.addUser(sessionId, userAccount);
            }
            request = new WrappedRequest(request, userAccount.getLogin());
            UserProfile userProfile = UserProfile.builder()
                    .login(userAccount.getLogin())
                    .password(userAccount.getPassword())
                    .roles(userAccount.getRoles())
                    .build();
            securityContext.addUser(userProfile);
        }
        filterChain.doFilter(request, response);
    }

    private boolean checkEndPoints(String path, String method) {
        return !(("POST".equalsIgnoreCase(method) && path.matches("[/]account[/]register[/]?"))
                || path.matches("[/]forum[/]posts([/]\\w+)+[/]?")); // + -> сколько угодно раз
    }

    private Optional<String[]> getCredential(String token) {
        String[] res = null;
        try {
            token = token.split(" ")[1]; // Basic || iWjNHBb873bGVgw7hBV
            byte[] bytesDecode = Base64.getDecoder().decode(token);
            token = new String(bytesDecode); // Декодируем
            res = token.split(":");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.ofNullable(res);
    }

    private static class WrappedRequest extends HttpServletRequestWrapper {
        String login;

        public WrappedRequest(HttpServletRequest request, String login) {
            super(request);
            this.login = login;
        }

        @Override
        public Principal getUserPrincipal() {
//            return new Principal() {
//                @Override
//                public String getName() {
//                    return login;
//                }
//            };
            return () -> login;
        }
    }
}
