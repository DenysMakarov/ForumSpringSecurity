package telran.security;

import org.springframework.stereotype.Service;
import telran.accountservise.model.User;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionServiceImpl implements SessionService{
    Map<String, User> userMap = new ConcurrentHashMap<>();
    @Override
    public User addUser(String sessionId, User user) {
        return userMap.put(sessionId, user);
    }

    @Override
    public User getUser(String sessionId) {
        return userMap.get(sessionId);
    }

    @Override
    public User removeUser(String sessionId) {
        return userMap.remove(sessionId);
    }
}
