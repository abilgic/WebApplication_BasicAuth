using Microsoft.AspNetCore.Authentication;
using Microsoft.OpenApi.Models;
using WebApplication_BasicAuth;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
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

builder.Services.AddAuthentication("BasicAuthentication")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseAuthentication(); // Kimlik doğrulama - kullanıcı adı şifre kontrolü yapar
app.UseAuthorization(); // Yetki kontrolü - kullanıcı yetkisi kontrolü yapar.

app.MapControllers();

app.Run();
