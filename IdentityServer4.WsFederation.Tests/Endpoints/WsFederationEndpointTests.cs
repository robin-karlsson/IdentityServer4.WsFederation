using System;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.WsFederation.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace IdentityServer4.WsFederation.Tests.Endpoints
{
    [TestClass]
    public class WsFederationEndpointTests
    {
        private readonly ILogger<WsFederationEndpoint> _logger = Substitute.For<ILogger<WsFederationEndpoint>>();
        private IWsFederationRequestValidator _validator;
        private IUserSession _userSession;
        private readonly DateTimeOffset _now = new DateTimeOffset(DateTime.UtcNow);

        private WsFederationSigninResponseGenerator GetDefaultResponseGenerator()
        {
            var clock = Substitute.For<ISystemClock>();
            clock.UtcNow.Returns(_now);

            var logger = Substitute.For<ILogger<WsFederationSigninResponseGenerator>>();

            var certificate = new X509Certificate2("IdentityServer4.WsFederation.Testing.pfx", "pw");
            var signingCredentials = new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
            var keys = Substitute.For<IKeyMaterialService>();
            keys.GetSigningCredentialsAsync().Returns(signingCredentials);

            var options = new IdentityServerOptions
            {
                IssuerUri = "http://example.com/testissuer"
            };

            return new WsFederationSigninResponseGenerator(logger, clock, options, keys, new InMemoryResourcesStore(new[] { new IdentityResource("name", new[] { JwtClaimTypes.Name }), new IdentityResources.Profile() }),
                new DefaultProfileService(Substitute.For<ILogger<DefaultProfileService>>()), new WsFederationOptions());
        }

        [TestMethod]
        public async Task PostShouldReturnInvalidMethod()
        {
            _userSession = Substitute.For<IUserSession>();
            var endpoint = new WsFederationEndpoint(_logger, _validator, GetDefaultResponseGenerator(), _userSession);
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "POST";
            var result = (StatusCodeResult)await endpoint.ProcessAsync(httpContext);

            Assert.AreEqual((int)HttpStatusCode.MethodNotAllowed, result.StatusCode);
        }

        [TestMethod]
        public async Task ShouldReturnCorrectTaskForSignInRequest()
        {
            _userSession = Substitute.For<IUserSession>();
            _userSession.GetUserAsync().Returns(Task.FromResult(
                new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {new Claim(JwtClaimTypes.Subject, "test"), new Claim(JwtClaimTypes.AuthenticationMethod,"test"), new Claim(JwtClaimTypes.Name,"test person") }))));
            _validator = new WsFederationRequestValidator(Substitute.For<ILogger<WsFederationRequestValidator>>(),
                new InMemoryClientStore(new[]
                {
                    new Client
                    {
                        ClientId = "http://sample-with-policyengine/",
                        ProtocolType = IdentityServerConstants.ProtocolTypes.WsFederation,
                        RedirectUris = new []{"http://localhost"},
                        AllowedScopes = { "openid", "profile" }
                    }
                }));
            
            var endpoint = new WsFederationEndpoint(_logger, _validator, GetDefaultResponseGenerator(), _userSession);
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "GET";
            httpContext.Request.QueryString = QueryString.FromUriComponent("?wa=wsignin1.0&wtrealm=http%3a%2f%2fsample-with-policyengine%2f");
            var result = await endpoint.ProcessAsync(httpContext);

            Assert.IsInstanceOfType(result,typeof(WsFederationSigninResult));
        }

        [TestMethod]
        public async Task ShouldReturnCorrectTaskForSignOutRequest()
        {
            _userSession = Substitute.For<IUserSession>();
            _userSession.GetUserAsync().Returns(Task.FromResult(
                new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim(JwtClaimTypes.Subject, "test"), new Claim(JwtClaimTypes.AuthenticationMethod, "test"), new Claim(JwtClaimTypes.Name, "test person") }))));
            _validator = new WsFederationRequestValidator(Substitute.For<ILogger<WsFederationRequestValidator>>(),
                new InMemoryClientStore(new[]
                {
                    new Client
                    {
                        ClientId = "http://sample-with-policyengine/",
                        ProtocolType = IdentityServerConstants.ProtocolTypes.WsFederation,
                        RedirectUris = new []{"http://localhost"},
                        AllowedScopes = { "openid", "profile" }
                    }
                }));

            var endpoint = new WsFederationEndpoint(_logger, _validator, GetDefaultResponseGenerator(), _userSession);
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "GET";
            httpContext.Request.QueryString = QueryString.FromUriComponent("?wa=wsignout1.0&wtrealm=http%3a%2f%2fsample-with-policyengine%2f");
            var result = await endpoint.ProcessAsync(httpContext);

            Assert.IsInstanceOfType(result, typeof(WsFederationSignOutResult));
        }

        [TestMethod]
        public async Task ShouldReturnCorrectTaskForInvalidRequest()
        {
            _userSession = Substitute.For<IUserSession>();
            _userSession.GetUserAsync().Returns(Task.FromResult(
                new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim(JwtClaimTypes.Subject, "test"), new Claim(JwtClaimTypes.AuthenticationMethod, "test"), new Claim(JwtClaimTypes.Name, "test person") }))));
            _validator = new WsFederationRequestValidator(Substitute.For<ILogger<WsFederationRequestValidator>>(),
                new InMemoryClientStore(new[]
                {
                    new Client
                    {
                        ClientId = "http://sample-with-policyengine/",
                        ProtocolType = IdentityServerConstants.ProtocolTypes.WsFederation,
                        RedirectUris = new []{"http://localhost"},
                        AllowedScopes = { "openid", "profile" }
                    }
                }));

            var endpoint = new WsFederationEndpoint(_logger, _validator, GetDefaultResponseGenerator(), _userSession);
            var httpContext = new DefaultHttpContext();
            httpContext.Request.Method = "GET";
            httpContext.Request.QueryString = QueryString.FromUriComponent("?wa=invalid1.0&wtrealm=http%3a%2f%2fsample-with-policyengine%2f");
            var result = await endpoint.ProcessAsync(httpContext);

            Assert.IsInstanceOfType(result, typeof(WsFederationErrorResult));
        }
    }
}
