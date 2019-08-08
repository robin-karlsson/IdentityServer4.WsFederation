using System;
using System.Collections.Generic;
using IdentityServer4.Configuration;
using IdentityServer4.Services;
using IdentityServer4.WsFederation.Validation;
using IdentityServer4.WsFederation.WsTrust.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;

namespace IdentityServer4.WsFederation
{
    public class WsFederationSigninResponseGenerator : IWsFederationResponseGenerator
    {
        private readonly ILogger _logger;
        private readonly ISystemClock _clock;
        private readonly IdentityServerOptions _options;
        private readonly IKeyMaterialService _keys;
        private readonly IResourceStore _resources;
        private readonly IProfileService _profile;
        private readonly WsFederationOptions _federationOptions;

        public WsFederationSigninResponseGenerator(ILogger<WsFederationSigninResponseGenerator> logger, ISystemClock clock, IdentityServerOptions options, IKeyMaterialService keys, IResourceStore resources, IProfileService profile, WsFederationOptions federationOptions)
        {
            _logger = logger;
            _clock = clock;
            _options = options;
            _keys = keys;
            _resources = resources;
            _profile = profile;
            _federationOptions = federationOptions;
        }

        public async Task<WsFederationSigninResponse> GenerateResponseAsync(ValidatedWsFederationRequest request)
        {
            _logger.LogDebug("Creating WsFederation Signin Response.");
            var responseMessage = new WsFederationMessage
            {
                IssuerAddress = request.RequestMessage.Wreply ?? "",
                Wa = request.RequestMessage.Wa,
                Wctx = request.RequestMessage.Wctx,
                Whr = request.RequestMessage.Whr,
                Wresult = await GenerateSerializedRstr(request)
            };

            var response = new WsFederationSigninResponse
            {
                Request = request,
                ResponseMessage = responseMessage
            };
            return response;
        }

        public async Task<string> GenerateSerializedRstr(ValidatedWsFederationRequest request)
        {
            var now = _clock.UtcNow.UtcDateTime;
            var credential = await _keys.GetSigningCredentialsAsync();
            var key = credential.Key as X509SecurityKey;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = request.RequestMessage.Wtrealm,
                Expires = now.AddSeconds(request.Client.IdentityTokenLifetime),
                IssuedAt = now,
                Issuer = _options.IssuerUri,
                NotBefore = now,
                SigningCredentials = key == null ? credential : new X509SigningCredentials(key.Certificate, _federationOptions.DefaultSignatureAlgorithm),
                Subject = await CreateSubjectAsync(request)
            };
            //For whatever reason, the Digest method isn't specified in the builder extensions for identity server.
            //Not a good solution to force the user to use the overload that takes SigningCredentials
            //IdentityServer4/Configuration/DependencyInjection/BuilderExtensions/Crypto.cs
            //Instead, it should be supported in:
            //  The overload that takes a X509Certificate2
            //  The overload that looks it up in a cert store
            //  The overload that takes an RsaSecurityKey
            //  AddDeveloperSigningCredential
            //For now, this is a workaround.
            if (tokenDescriptor.SigningCredentials.Digest == null)
            {
                _logger.LogInformation($"SigningCredentials does not have a digest specified. Using default digest algorithm of {SecurityAlgorithms.Sha256Digest}");
                tokenDescriptor.SigningCredentials = new SigningCredentials(tokenDescriptor.SigningCredentials.Key, tokenDescriptor.SigningCredentials.Algorithm ?? _federationOptions.DefaultSignatureAlgorithm, _federationOptions.DefaultDigestAlgorithm);
            }

            _logger.LogDebug("Creating SAML 2.0 security token.");
            
            var tokenHandler = new Saml2SecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            _logger.LogDebug("Serializing RSTR.");
            var rstr = new RequestSecurityTokenResponse
            {
                AppliesTo = new AppliesTo(request.RequestMessage.Wtrealm),
                KeyType = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey",
                Lifetime = new Lifetime
                {
                    Created = XmlConvert.ToString(now, XmlDateTimeSerializationMode.Utc),
                    Expires = XmlConvert.ToString(now.AddSeconds(request.Client.IdentityTokenLifetime),XmlDateTimeSerializationMode.Utc),
                },
                RequestedSecurityToken = token,
                RequestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue",
                TokenType = WsFederationConstants.TokenTypes.Saml2TokenProfile11
            };
            return RequestSecurityTokenResponseSerializer.Serialize(rstr);
        }


        protected async Task<ClaimsIdentity> CreateSubjectAsync(ValidatedWsFederationRequest result)
        {
            var requestedClaimTypes = new List<string>();

            var resources = await _resources.FindEnabledIdentityResourcesByScopeAsync(result.Client.AllowedScopes);
            foreach (var resource in resources)
            {
                foreach (var claim in resource.UserClaims)
                {
                    requestedClaimTypes.Add(claim);
                }
            }

            var ctx = new ProfileDataRequestContext
            {
                Subject = result.Subject,
                RequestedClaimTypes = requestedClaimTypes,
                Client = result.Client,
                Caller = "WS-Federation"
            };

            await _profile.GetProfileDataAsync(ctx);

            // map outbound claims
            var nameid = new Claim(ClaimTypes.NameIdentifier, result.Subject.GetSubjectId());
            nameid.Properties[ClaimProperties.SamlNameIdentifierFormat] = _federationOptions.DefaultSamlNameIdentifierFormat;

            var outboundClaims = new List<Claim> { nameid };
            foreach (var claim in ctx.IssuedClaims)
            {
                if (_federationOptions.DefaultClaimMapping.TryGetValue(claim.Type, out var type))
                {
                    var outboundClaim = new Claim(type, claim.Value, claim.ValueType);
                    if (outboundClaim.Type == ClaimTypes.NameIdentifier)
                    {
                        outboundClaim.Properties[ClaimProperties.SamlNameIdentifierFormat] = _federationOptions.DefaultSamlNameIdentifierFormat;
                    }

                    outboundClaims.Add(outboundClaim);
                }
                else if (_federationOptions.DefaultTokenType != WsFederationConstants.TokenTypes.Saml11TokenProfile11)
                {
                    outboundClaims.Add(claim);
                }
                else
                {
                    _logger.LogInformation("No explicit claim type mapping for {claimType} configured. Saml11 requires a URI claim type. Skipping.", claim.Type);
                }
            }

            // The AuthnStatement statement generated from the following 2
            // claims is mandatory for some service providers (i.e. Shibboleth-Sp). 
            // The value of the AuthenticationMethod claim must be one of the constants in
            // System.IdentityModel.Tokens.AuthenticationMethods.
            // Password is the only one that can be directly matched, everything
            // else defaults to Unspecified.
            if (result.Subject.GetAuthenticationMethod() == OidcConstants.AuthenticationMethods.Password)
            {
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, OidcConstants.AuthenticationMethods.Password));
            }
            else
            {
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, "Unspecified"));
            }

            // authentication instant claim is required
            outboundClaims.Add(new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, "yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime));

            return new ClaimsIdentity(outboundClaims, "idsrv");
        }
    }
}
