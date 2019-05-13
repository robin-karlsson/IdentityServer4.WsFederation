using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace IdentityServer4.WsFederation.Behavior
{
    public class WsFederationRedirectEndSessionRequestValidator : IEndSessionRequestValidator
    {
        private readonly EndSessionRequestValidator _validator;
        private readonly IEnumerable<Client> _clients;
        private readonly ILogger<WsFederationRedirectEndSessionRequestValidator> _logger;

        public WsFederationRedirectEndSessionRequestValidator(EndSessionRequestValidator validator, IEnumerable<Client> clients, IHttpContextAccessor context, IdentityServerOptions options, ITokenValidator tokenValidator, IRedirectUriValidator uriValidator, IUserSession userSession, IClientStore clientStore, IMessageStore<EndSession> endSessionMessageStore, ILogger<WsFederationRedirectEndSessionRequestValidator> logger)
        {
            _validator = validator;
            _clients = clients;
            _logger = logger;
        }

        public async Task<EndSessionValidationResult> ValidateAsync(NameValueCollection parameters, ClaimsPrincipal subject)
        {
            _logger.LogDebug("Start end session request validation");

            var result = await _validator.ValidateAsync(parameters, subject);
            var logoutRedirectUri = parameters.Get(OidcConstants.EndSessionRequest.PostLogoutRedirectUri);
            if (!result.IsError && !string.IsNullOrEmpty(logoutRedirectUri) &&
                (result.ValidatedRequest.Client == null || result.ValidatedRequest.Client.ProtocolType ==
                 IdentityServerConstants.ProtocolTypes.WsFederation))
            {
                var client = result.ValidatedRequest.Client ??
                             _clients.FirstOrDefault(c => c.ProtocolType == IdentityServerConstants.ProtocolTypes.WsFederation && c.PostLogoutRedirectUris.Contains(logoutRedirectUri));
                if (client != null)
                {
                    result.ValidatedRequest.PostLogOutUri = logoutRedirectUri;
                }
                else
                {
                    _logger.LogWarning($"No client found with log out redirect uri {logoutRedirectUri}");
                }
            }

            return result;
        }

        public Task<EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters)
        {
            return _validator.ValidateCallbackAsync(parameters);
        }
    }
}
