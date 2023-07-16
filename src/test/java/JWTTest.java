import com.dashspring.JWT;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class JWTTest {
    private static final JWT jwt = JWT.getInstance();
    private static String token;

    @BeforeAll
    static void generateToken() {
        token = jwt.generate("Dash");
    }

    @Test
    @DisplayName("Generating JWT Token")
    void tokenGen() {
        assertNotNull(token);
    }

    @Test
    @DisplayName("Validate JWT Token")
    void validateToken() {
        assertTrue(jwt.validate(token, "Dash"));
        assertFalse(jwt.validate(token, "Other"));
    }

    @Test
    @DisplayName("Validate and get username")
    void validateAndGetUserName() throws IllegalAccessException {
        assertEquals("Dash", jwt.validateAndGetUserName(token));
        assertThrows(Exception.class, () -> jwt.validateAndGetUserName("other"));
    }

    @Test
    @DisplayName("Expiry token")
    void expiry() {
        assertThrows(IllegalAccessException.class,
                () -> jwt.validateAndGetUserName(
                        JWT.getInstance().setExpiry(0L).generate("Dash")
                )
        );
    }
}
