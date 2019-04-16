using IdentityServer4.Endpoints.Results;
using IdentityServer4.Hosting;
using IdentityServer4.Services;
using IdentityServer4.WsFederation.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsFederation;
using System.Net;
using System.Threading.Tasks;

namespace IdentityServer4.WsFederation
{
    public class WsFederationEndpoint : IEndpointHandler
    {
        private readonly ILogger _logger;
        private readonly IWsFederationRequestValidator _validator;
        private readonly IWsFederationResponseGenerator _responseGenerator;
        private readonly IUserSession _userSession;

        public WsFederationEndpoint(ILogger<WsFederationEndpoint> logger, IWsFederationRequestValidator validator, IWsFederationResponseGenerator responseGenerator, IUserSession userSession)
        {
            _logger = logger;
            _validator = validator;
            _responseGenerator = responseGenerator;
            _userSession = userSession;
        }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            _logger.LogDebug("Processing WsFederation request.");

            if (!HttpMethods.IsGet(context.Request.Method))
            {
                _logger.LogWarning($"WsFederation endpoint only supports GET requests. Current method is {context.Request.Method}");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            var user = await _userSession.GetUserAsync();

            var queryString = context.Request.QueryString;
            _logger.LogDebug($"Proccessing WsFederation request with QueryString: {queryString}.");

            var message = WsFederationMessage.FromQueryString(queryString.Value);
            var validationResult = await _validator.ValidateAsync(message, user);

            if (validationResult.IsError)
            {
                _logger.LogError("WsFederation request validation failed.");
                return new WsFederationErrorResult(new WsFederationErrorResponse {
                    Request = validationResult.ValidatedRequest,
                    Error = validationResult.Error,
                    ErrorDescription = validationResult.ErrorDescription
                });
            }

            if (validationResult.ValidatedRequest.RequestMessage.IsSignOutMessage)
            {
                return new WsFederationSignOutResult();
            }

            //if needed, show login page
            if(user == null)
            {
                _logger.LogInformation("User is null. Showing login page.");
                return new WsFederationLoginPageResult(validationResult.ValidatedRequest);
            }

            //Otherwise, return result
            var response = await _responseGenerator.GenerateResponseAsync(validationResult.ValidatedRequest);

            _logger.LogTrace("End get WsFederation signin request.");
            return new WsFederationSigninResult(response);
        }
    }
}
