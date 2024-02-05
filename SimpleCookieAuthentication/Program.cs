var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "http";

}).AddCookie("http", options =>
{
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.AccessDeniedPath = "/Forbidden/";
})
.AddJwtBearer("token",options => 
{
    var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("SuperSecretKeyForSecuringAllTheImportantEndPoints"));
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateIssuer = true,
        ValidIssuer = "Issuer",
        ValidAudience = "Audience",
        ValidateLifetime = true
    };
});
var app = builder.Build();
app.UseAuthentication();

app.MapGet("/secured", (context) =>
{
    var hasClaim = context.User.HasClaim("name", "anton");
    if (!hasClaim) 
    {
        context.Response.StatusCode = 403;
        return Task.CompletedTask;
    }
    var user = context.User;
    var name = user.FindFirstValue("name");
    var role = user.FindFirstValue(ClaimTypes.Role);
    return context.Response.WriteAsync($"name: {name}, role: {role}, claim {hasClaim}");
});

app.MapGet("/login", async (context) =>
{
    var claims = new List<Claim>()
    {
        new(ClaimTypes.Role, "Administrator"),
        new("name", "anton")
    };
    var claimsIdentity = new ClaimsIdentity(claims, "http");
    var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
    await context.SignInAsync("http", claimsPrincipal);
});


app.Run();
