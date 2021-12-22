package telran.accountservise.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(of = {"login"})
@Document(collection = "users")
public class User {
    @Id
    String login;
    String firstName;
    String lastName;
    String password;
    Set<String> roles = new HashSet<>();


    public User(String login, String firstName, String lastName, String password) {
        this.login = login;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
    }

//    public void removeRole(String role){
//        roles.remove(role);
//    }
}

