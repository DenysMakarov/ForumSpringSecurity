package telran.security;

import telran.accountservise.model.User;

public interface SessionService {
    User addUser(String sessionId, User user);

    User getUser(String sessionId);

    User removeUser(String sessionId);
}
