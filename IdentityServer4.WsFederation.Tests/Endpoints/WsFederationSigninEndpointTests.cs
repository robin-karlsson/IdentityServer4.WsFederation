using System.Net;
using System.Threading.Tasks;
using IdentityServer4.Configuration;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Services;
using IdentityServer4.WsFederation.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace IdentityServer4.WsFederation.Tests.Endpoints
{
    [TestClass]
    public class WsFederationSigninEndpointTests
    {
        private readonly ILogger<WsFederationEndpoint> _logger = Substitute.For<ILogger<WsFederationEndpoint>>();
        private IdentityServerOptions _options;
        private IWsFederationRequestValidator _validator;
        private IWsFederationResponseGenerator _responseGenerator;
        private IUserSession _userSession;

        [TestMethod]
        public async Task PostShouldReturnInvalidMethod()
        {
            var endpoint = new WsFederationEndpoint(_logger, _validator, _responseGenerator, _userSession);
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            var result = (StatusCodeResult)await endpoint.ProcessAsync(httpContext);

            Assert.AreEqual((int)HttpStatusCode.MethodNotAllowed, result.StatusCode);
        }
    }
}
