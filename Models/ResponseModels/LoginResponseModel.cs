namespace JWT.ResponseModels;

public class LoginResponseModel
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}