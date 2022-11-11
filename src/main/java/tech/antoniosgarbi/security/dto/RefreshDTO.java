package tech.antoniosgarbi.security.dto;

public class RefreshDTO {
    private String refreshToken;

    public RefreshDTO() { }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
