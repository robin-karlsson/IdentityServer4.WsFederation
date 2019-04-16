using System.Threading.Tasks;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSignOutResult : IEndpointResult
    {
        public Task ExecuteAsync(HttpContext context)
        {
            context.Response.Redirect("../connect/endsession");
            return Task.CompletedTask;
        }
    }
}