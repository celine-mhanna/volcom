package com.vc.volunteeringcommunity.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.time.Instant;

@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username")
        })
public class User implements Serializable {

    @JsonIgnore
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotBlank
    @Size(max = 255)
    private String username;

    @NotBlank
    @Size(max = 255)
    @Column(name = "display_name")
    private String displayName;

    @Column(name = "password_needs_reset")
    private boolean passwordNeedsReset;

    @JsonIgnore
    @NotBlank
    @Size(max = 60)
    private String password;

    @JsonIgnore
    @NotBlank
    @Size(max = 120)
    private String role;

    @JsonIgnore
    @CreationTimestamp
    @Column(updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        isActive = true;
    }

    @JsonIgnore
    @UpdateTimestamp
    private Instant updatedAt;

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    private Boolean isActive;

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPassword() {
        return password;
    }

    public String getRole() {
        return role;
    }

    public Boolean getActive() {
        return isActive;
    }

    public boolean passwordNeedsReset() {
        return passwordNeedsReset;
    }

    public static final class UserBuilder {
        private Long id;
        private String username;
        private String displayName;
        private String password;
        private boolean passwordNeedsReset;
        private String role;
        private Boolean isActive;

        public UserBuilder() {
        }

        public static UserBuilder anUser() {
            return new UserBuilder();
        }

        public UserBuilder withId(Long id) {
            this.id = id;
            return this;
        }

        public UserBuilder withUsername(String username) {
            this.username = username;
            return this;
        }

        public UserBuilder withDisplayName(String displayName) {
            this.displayName = displayName;
            return this;
        }

        public UserBuilder withPassword(String password) {
            this.password = password;
            return this;
        }

        public UserBuilder withPasswordNeedsReset(boolean passwordNeedsReset){
            this.passwordNeedsReset = passwordNeedsReset;
            return this;
        }

        public UserBuilder withRole(String role) {
            this.role = role;
            return this;
        }

        public UserBuilder withIsActive(Boolean isActive) {
            this.isActive = isActive;
            return this;
        }

        public User build() {
            User user = new User();
            user.displayName = this.displayName;
            user.role = this.role;
            user.isActive = this.isActive;
            user.username = this.username;
            user.password = this.password;
            user.passwordNeedsReset = this.passwordNeedsReset;
            user.id = this.id;
            return user;
        }
    }
}
