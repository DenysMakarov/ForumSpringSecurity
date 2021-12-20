package telran.accountservise.model;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import telran.accountservise.dao.UserMongoRepository;
import telran.accountservise.dto.exceptions.UserNotFondException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

@Service
public class AuthenticationFilter implements Filter {

    UserMongoRepository repository;

    @Autowired
    public AuthenticationFilter(UserMongoRepository repository) {
        this.repository = repository;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (checkEndPoints(request.getServletPath(), request.getMethod())) {
            String token = request.getHeader("Authorization");
            if (token == null) {
                response.sendError(401, "Header Authorization not fond");
                return;
            }
            String[] credentials = getCredential(token).orElse(null);
            if (credentials == null || credentials.length < 2) {
                response.sendError(401, "Token not valid");
                return;
            }
            User user = repository.findById(credentials[0]).orElse(null);
            if (user == null) {
                response.sendError(401, "User not valid");
                return;
            }
            if (!credentials[1].equals(user.getPassword())) {
                response.sendError(401, "User or pass not a valid");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean checkEndPoints(String path, String method) {
//        return !("POST".equalsIgnoreCase(method) && path.matches("[/]account[/]register[/]?]"));
           return  !(
                ("POST".equalsIgnoreCase(method) && path.matches("[/]account[/]register[/]?]"))
                || path.matches("[/]forum[/]posts([/]\\w+)+[/]?")
        );
//        return false;
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
}
