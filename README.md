Authentication & Authorization

We are creating a new Web API project.

The project we created looks as follows:

We enable the authentication feature in the API. To do this, we open the Program.cs file. Then, we add the following line to the middleware layer:

app.UseAuthentication();
Next, we add the following lines to the services:

builder.Services.AddAuthentication("BasicAuthentication")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);
After that, we define the BasicAuthenticationHandler class:

public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var endpoint = Context.GetEndpoint();
        if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
        {
            return AuthenticateResult.NoResult();
        }
        if (Request.Headers.ContainsKey("Authorization") == false)
        {
            return AuthenticateResult.Fail("Authorization header not found.");
        }

        var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
        var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
        var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
        var username = credentials[0];
        var password = credentials[1];

        bool result = (username == "test" && password == "123123") ? true : false;
        if (result)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "99"),
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "user")
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
        else
        {
            return AuthenticateResult.Fail("Invalid username or password.");
        }
    }
}
Then, we move to the Controller and add the [Authorize] attribute. Thanks to this attribute, the requests we make from Swagger will undergo an authorization check.

We open Swagger and click the Try it out button under the WeatherForecast GET method on the page.

Then, we click the Execute button that appears.

When we click the Execute button, we receive an unauthorized response. The reason for this is that, as mentioned before, the [Authorize] attribute in the controller is active, causing the BasicAuthenticationHandler class to invoke the HandleAuthenticateAsync method.

Let’s try this API call using Postman as well.
First, we open Postman. Then, we click the New button on the left.

In the window that appears, we click on the HTTP option.

Next, on the opened screen, we copy the endpoint address from Swagger (http://localhost:5082/WeatherForecast) and paste it here.

When we click the Send button, we receive an unauthorized response.

Then, we click on the Authorization tab.

On the tab that opens, we fill in the username and password fields.

These values are taken from the ones we defined earlier in our project's BasicAuthenticationHandler class.

After entering these values, we click the Send button.

As you can see, we receive a 200 OK response along with a response payload.

If we want to allow only users with roles such as admin to execute certain methods, we define the required role in the [Authorize] attribute as follows:

In this case, if the user has the admin role defined, the method they call will be executed. For this, we define the admin role in the BasicAuthenticationHandler class.

To enable basic authentication in Swagger, we add the following code to the AddSwaggerGen service in Program.cs:

builder.Services.AddSwaggerGen(c=>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo { Title = "WebApplication_BasicAuth", Version = "V1" });
    c.AddSecurityDefinition("basic", new OpenApiSecurityScheme
        {
        Description = "Burada basic auth bilgilerinizi giriniz.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Scheme = "basic",
        Type=SecuritySchemeType.Http
});
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme , Id="basic"}
            },
                new List<string>()
            }

    });
});

Then, when we run the project, the Authorize button in Swagger becomes active.

To authorize, we click the button, enter the username and password, and click the Authorize button.

After that, we see that the lock icon on the authorize button is open, indicating that we are authorized.

Finally, when we send a request to the WeatherForecast API, we see that it returns a response and works correctly.
