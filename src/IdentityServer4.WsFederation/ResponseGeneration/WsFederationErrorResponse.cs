using IdentityServer4.WsFederation.Validation;

namespace IdentityServer4.WsFederation
{
    public class WsFederationErrorResponse
    {
        public ValidatedWsFederationRequest Request { get; set; }

        public string Error { get; set; }
        public string ErrorDescription { get; set; }
    }
}