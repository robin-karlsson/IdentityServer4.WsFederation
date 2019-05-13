using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.WsFederation.Behavior
{
    public class AuthenticationServiceWithFallback : AuthenticationService
    {
        public AuthenticationServiceWithFallback(IAuthenticationSchemeProvider schemes, IAuthenticationHandlerProvider handlers, IClaimsTransformation transform) : base(schemes, handlers, transform)
        {
        }

        public override async Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
        {
            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                scheme = null;
            }
            return await base.AuthenticateAsync(context, scheme);
        }

        public override async Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            var handler = await Handlers.GetHandlerAsync(context, scheme);
            if (handler == null)
            {
                scheme = null;
            }

            await base.ChallengeAsync(context, scheme, properties);
        }
    }
}