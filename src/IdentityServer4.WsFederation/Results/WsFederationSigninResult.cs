using IdentityServer4.Hosting;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSigninResult : IEndpointResult
    {
        public WsFederationSigninResponse Response { get; }

        public WsFederationSigninResult(WsFederationSigninResponse response)
        {
            Response = response;
        }

        private IUserSession _userSession;

        public async Task ExecuteAsync(HttpContext context)
        {
            _userSession = _userSession ?? context.RequestServices.GetRequiredService<IUserSession>();

            await ProcessResponseAsync(context);
        }

        private async Task ProcessResponseAsync(HttpContext context)
        {
            await _userSession.AddClientIdAsync(Response.Request.Client.ClientId);

            var formPost = Response.ResponseMessage.BuildFormPost();
            context.Response.ContentType = "text/html";
            await context.Response.WriteHtmlAsync(formPost);
        }
    }
}
