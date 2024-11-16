using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using BTCPayServer.Client;
using BTCPayServer.Data;
using BTCPayServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BTCPayServer.Security.Greenfield
{
    public class BasicAuthenticationHandler : AuthenticationHandler<GreenfieldAuthenticationOptions>
    {
        private readonly IOptionsMonitor<IdentityOptions> _identityOptions;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public BasicAuthenticationHandler(
            IOptionsMonitor<IdentityOptions> identityOptions,
            IOptionsMonitor<GreenfieldAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager) : base(options, logger, encoder)
        {
            _identityOptions = identityOptions;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authHeader = Context.Request.Headers["Authorization"];

            if (!IsValidAuthHeader(authHeader))
                return AuthenticateResult.NoResult();
            string password;
            string username;
            try
            {
                var encodedUsernamePassword =
                    authHeader.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[1]?.Trim();
                var decodedUsernamePassword =
                    Encoding.UTF8.GetString(Convert.FromBase64String(encodedUsernamePassword)).Split(':');
                username = decodedUsernamePassword[0];
                password = decodedUsernamePassword[1];
            }
            catch (Exception)
            {
                return AuthenticateResult.Fail(
                    "Basic authentication header was not in a correct format. (username:password encoded in base64)");
            }

            var result = await _signInManager.PasswordSignInAsync(username, password, true, true);
            if (!result.Succeeded)
                return AuthenticateResult.Fail(result.ToString());

            var user = await _userManager.Users
                .Include(applicationUser => applicationUser.Fido2Credentials)
                .FirstOrDefaultAsync(applicationUser =>
                    applicationUser.NormalizedUserName == _userManager.NormalizeName(username));

            if (!UserService.TryCanLogin(user, out var error))
            {
                return AuthenticateResult.Fail($"Basic authentication failed: {error}");
            }
            if (user.Fido2Credentials.Any())
            {
                return AuthenticateResult.Fail("Cannot use Basic authentication with multi-factor is enabled.");
            }
            var claims = new List<Claim>()
            {
                new Claim(_identityOptions.CurrentValue.ClaimsIdentity.UserIdClaimType, user.Id),
                new Claim(GreenfieldConstants.ClaimTypes.Permission,
                    Permission.Create(Policies.Unrestricted).ToString())
            };
            claims.AddRange((await _userManager.GetRolesAsync(user)).Select(s => new Claim(_identityOptions.CurrentValue.ClaimsIdentity.RoleClaimType, s)));

            return AuthenticateResult.Success(new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity(claims, GreenfieldConstants.AuthenticationType)),
                GreenfieldConstants.AuthenticationType));
        }

        private bool IsValidAuthHeader(string authHeader)
        {
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var parts = authHeader.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
            {
                return false;
            }

            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
                var usernamePassword = decoded.Split(':');
                if (usernamePassword.Length != 2)
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
