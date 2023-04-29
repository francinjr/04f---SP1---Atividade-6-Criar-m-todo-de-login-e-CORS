using Exo.WebApi.Contexts;
using Exo.WebApi.Repositories;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ExoContext, ExoContext>();
builder.Services.AddControllers();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = "JwtBearer";
        options.DefaultChallengeScheme = "JwtBearer";
    })
    .AddJwtBearer("JwtBearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        { 
            // valida quem está solicitando
            ValidateIssuer = true,
            // valida quem está recebendo
            ValidateAudience = true,
            // Define se o tempo de expiração é validado
            ValidateLifetime = true,
            // Criptografia e validação da chave de autenticação
            IssuerSigningKey = new
            SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chave-autenticacao")),
            // Valida o tempo de expiração do token
            ClockSkew = TimeSpan.FromMinutes(30),
            // Nome do issuer, da origem
            ValidIssuer = "exoapi.webapi",
            // Nome do audicente, para o destino.
            ValidAudience = "exoapi.webapi"
        };
    });
builder.Services.AddTransient<ProjetoRepository, ProjetoRepository>();
builder.Services.AddTransient<UsuarioRepository, UsuarioRepository>();

var app = builder.Build();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
