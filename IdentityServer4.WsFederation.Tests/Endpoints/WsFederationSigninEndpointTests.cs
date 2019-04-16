﻿using IdentityServer4.Configuration;
using IdentityServer4.Services;
using IdentityServer4.WsFederation.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace IdentityServer4.WsFederation.Tests.Endpoints
{
    [TestClass]
    public class WsFederationSigninEndpointTests
    {
        private ILogger _logger = Substitute.For<ILogger<WsFederationEndpoint>>();
        private IdentityServerOptions _options;
        private IWsFederationRequestValidator _validator;
        private IWsFederationResponseGenerator _responseGenerator;
        private IUserSession _userSession;

        [TestMethod]
        public void PostShouldReturnInvalidMethod()
        {

        }
    }
}
