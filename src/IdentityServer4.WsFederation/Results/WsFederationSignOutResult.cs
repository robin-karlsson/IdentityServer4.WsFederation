using System;
using System.Threading.Tasks;
using IdentityServer4.Hosting;
using IdentityServer4.WsFederation.Validation;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSignOutResult : IEndpointResult
    {
        private readonly ValidatedWsFederationRequest _validatedRequest;

        public WsFederationSignOutResult(ValidatedWsFederationRequest validatedRequest)
        {
            _validatedRequest = validatedRequest;
        }

        public Task ExecuteAsync(HttpContext context)
        {
            context.Response.Redirect("../connect/endsession?post_logout_redirect_uri=" + Uri.EscapeDataString(_validatedRequest.RequestMessage.Wreply));
            return Task.CompletedTask;
        }
    }
}